package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// databaseCollectorID is the stable id this collector is credited with.
const databaseCollectorID = "collector:azure.database"

// DatabaseCollector reads the tenant's Azure managed database services, the Azure
// counterpart of the AWS RDS collector. It covers the four subscription-listable
// engines: Azure SQL servers, PostgreSQL and MySQL flexible servers, and Cosmos DB
// accounts. Each is read with a single read-only List by subscription; no data-plane
// value, connection string, or key is retrieved (invariant: never retrieve secret
// values). Individual databases inside a server are the equivalent of table contents
// and are deliberately out of scope, the same boundary the AWS RDS collector draws at
// the instance and cluster level.
//
// Each server or account becomes a data-store node keyed by its ARM resource id,
// carrying its security posture (public network access, TLS floor, authentication
// mode, encryption, backup redundancy). Cross-references are recorded as id facts so
// later collectors and the reachability and identity engines can join: a
// customer-managed-key URI onto the key vault node, the Azure AD administrator's
// object id onto the Entra principal nodes, a delegated subnet onto the network
// nodes. SQL servers and Cosmos accounts expose a managed identity; that run-as
// relationship is emitted as an assumes edge to the identity's principal, exactly as
// the compute collector does for virtual machines. Per ADR-0019 §3 no verdict is
// synthesized: not-configured is an explicit fact, denied is a represented gap.
type DatabaseCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewDatabaseCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewDatabaseCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *DatabaseCollector {
	return &DatabaseCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newDatabaseCollector is the injectable constructor tests use with a stub API.
func newDatabaseCollector(tenantID string, api armAPI) *DatabaseCollector {
	return &DatabaseCollector{tenantID: tenantID, api: api}
}

func (c *DatabaseCollector) ID() string               { return databaseCollectorID }
func (c *DatabaseCollector) Provider() model.Provider { return model.Azure }

func databaseRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Azure, Profile: permissions.Discovery, Permission: p, By: databaseCollectorID}
	}
	return []permissions.Requirement{
		req("Microsoft.Sql/servers/read"),
		req("Microsoft.DBforPostgreSQL/flexibleServers/read"),
		req("Microsoft.DBforMySQL/flexibleServers/read"),
		req("Microsoft.DocumentDB/databaseAccounts/read"),
	}
}

func init() {
	for _, r := range databaseRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *DatabaseCollector) Requirements() []permissions.Requirement { return databaseRequirements() }

// dbResource is one database engine's list: its completeness service name, ARM
// provider path, API version, optional extra query, and a page decoder. The API
// versions differ per resource provider, each doc-verified fresh.
type dbResource struct {
	service    string
	path       string
	apiVersion string
	query      string
	decode     func(c *DatabaseCollector, sink collect.Sink, raw json.RawMessage) (int, error)
}

func (c *DatabaseCollector) resources() []dbResource {
	return []dbResource{
		{"database.sqlServers", "Microsoft.Sql/servers", "2025-01-01", "&$expand=administrators/activedirectory", (*DatabaseCollector).decodeSQLServers},
		{"database.postgresqlServers", "Microsoft.DBforPostgreSQL/flexibleServers", "2024-08-01", "", (*DatabaseCollector).decodePostgreSQL},
		{"database.mysqlServers", "Microsoft.DBforMySQL/flexibleServers", "2023-12-30", "", (*DatabaseCollector).decodeMySQL},
		{"database.cosmosAccounts", "Microsoft.DocumentDB/databaseAccounts", "2026-03-15", "", (*DatabaseCollector).decodeCosmos},
	}
}

// Collect enumerates the accessible subscriptions and lists each database engine in
// each. One completeness record is produced per (engine, subscription), plus
// database.subscriptions.
func (c *DatabaseCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "database.subscriptions", tenantScope, subscriptionsAPIVersion,
		fmt.Sprintf("%s/subscriptions?api-version=%s", armBaseURL, subscriptionsAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []subscription
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			subs = append(subs, page...)
			return len(page), nil
		})
	if err != nil {
		return err
	}

	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sub.SubscriptionID == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: sub.SubscriptionID, Name: sub.DisplayName,
			Attributes: attrs("state", sub.State)})
		scope := collect.Scope{Account: c.tenantID, Resource: sub.SubscriptionID}
		for _, r := range c.resources() {
			decode := r.decode
			_ = c.pageThrough(ctx, sink, r.service, scope, r.apiVersion,
				fmt.Sprintf("%s/subscriptions/%s/providers/%s?api-version=%s%s", armBaseURL, sub.SubscriptionID, r.path, r.apiVersion, r.query),
				func(raw json.RawMessage) (int, error) { return decode(c, sink, raw) })
		}
	}
	return nil
}

// runAsEdges emits the assumes edge from a database resource to each managed identity
// it can act as: the system-assigned identity and each user-assigned identity, keyed
// by principal id so they dedup with the Entra and RBAC principal nodes. This mirrors
// the compute collector's VM run-as edges.
func (c *DatabaseCollector) runAsEdges(sink collect.Sink, sourceID string, id *azureManagedIdentity) {
	if id == nil {
		return
	}
	emit := func(principalID string) {
		if principalID == "" {
			return
		}
		_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: principalID, Attributes: attrs("principal_type", "ManagedIdentity")})
		_ = sink.Link(collect.Link{SourceNativeID: sourceID, TargetNativeID: principalID, Kind: model.EdgeAssumes})
	}
	emit(id.PrincipalID)
	for _, ua := range id.UserAssignedIdentities {
		emit(ua.PrincipalID)
	}
}

// azureManagedIdentity is the managed-identity block shared across the SQL, Cosmos,
// and flexible-server resources (system-assigned principal plus user-assigned map).
type azureManagedIdentity struct {
	Type                   string `json:"type"`
	PrincipalID            string `json:"principalId"`
	UserAssignedIdentities map[string]struct {
		PrincipalID string `json:"principalId"`
	} `json:"userAssignedIdentities"`
}

func (c *DatabaseCollector) decodeSQLServers(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []sqlServer
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, s := range page {
		if s.ID == "" {
			continue
		}
		p := s.Properties
		a := map[string]string{
			"azure_type":                       "sql_server",
			"engine":                           "sql",
			"location":                         s.Location,
			"version":                          p.Version,
			"state":                            p.State,
			"fully_qualified_domain_name":      p.FullyQualifiedDomainName,
			"administrator_login":              p.AdministratorLogin,
			"public_network_access":            p.PublicNetworkAccess,
			"minimal_tls_version":              p.MinimalTLSVersion,
			"restrict_outbound_network_access": p.RestrictOutboundNetworkAccess,
			"cmk_key_uri":                      p.KeyID,
			"private_endpoint_count":           strconv.Itoa(len(p.PrivateEndpointConnections)),
		}
		if adm := p.Administrators; adm != nil {
			a["aad_admin_login"] = adm.Login
			// Forward key: the AAD admin's object id joins onto the Entra principal nodes.
			a["aad_admin_sid"] = adm.SID
			a["aad_admin_principal_type"] = adm.PrincipalType
			a["aad_only_authentication"] = boolAttr(adm.AzureADOnlyAuthentication)
		}
		mapTags(a, s.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: s.ID, Name: s.Name, Attributes: pruneEmptyAzure(a)})
		c.runAsEdges(sink, s.ID, s.Identity)
	}
	return len(page), nil
}

func (c *DatabaseCollector) decodePostgreSQL(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []flexibleServer
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, s := range page {
		if s.ID == "" {
			continue
		}
		a := flexibleServerAttrs(s, "postgresql_flexible_server", "postgresql")
		if ac := s.Properties.AuthConfig; ac != nil {
			a["active_directory_auth"] = ac.ActiveDirectoryAuth
			a["password_auth"] = ac.PasswordAuth
		}
		mapTags(a, s.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: s.ID, Name: s.Name, Attributes: pruneEmptyAzure(a)})
		c.runAsEdges(sink, s.ID, s.Identity)
	}
	return len(page), nil
}

func (c *DatabaseCollector) decodeMySQL(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []flexibleServer
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, s := range page {
		if s.ID == "" {
			continue
		}
		a := flexibleServerAttrs(s, "mysql_flexible_server", "mysql")
		mapTags(a, s.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: s.ID, Name: s.Name, Attributes: pruneEmptyAzure(a)})
		c.runAsEdges(sink, s.ID, s.Identity)
	}
	return len(page), nil
}

// flexibleServerAttrs maps the fields PostgreSQL and MySQL flexible servers share.
func flexibleServerAttrs(s flexibleServer, azureType, engine string) map[string]string {
	p := s.Properties
	a := map[string]string{
		"azure_type":                  azureType,
		"engine":                      engine,
		"location":                    s.Location,
		"version":                     p.Version,
		"state":                       p.State,
		"fully_qualified_domain_name": p.FullyQualifiedDomainName,
		"administrator_login":         p.AdministratorLogin,
	}
	if n := p.Network; n != nil {
		a["public_network_access"] = n.PublicNetworkAccess
		// Forward key: a delegated subnet joins onto the network collector's subnet node.
		a["delegated_subnet_id"] = n.DelegatedSubnetResourceID
	}
	if e := p.DataEncryption; e != nil {
		a["data_encryption_type"] = e.Type
		a["cmk_key_uri"] = e.PrimaryKeyURI
	}
	if h := p.HighAvailability; h != nil {
		a["high_availability_mode"] = h.Mode
	}
	if b := p.Backup; b != nil {
		a["geo_redundant_backup"] = b.GeoRedundantBackup
	}
	if st := p.Storage; st != nil {
		a["storage_auto_grow"] = st.AutoGrow
		if st.StorageSizeGB != 0 {
			a["storage_size_gb"] = strconv.Itoa(st.StorageSizeGB)
		}
	}
	return a
}

func (c *DatabaseCollector) decodeCosmos(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []cosmosAccount
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, ca := range page {
		if ca.ID == "" {
			continue
		}
		p := ca.Properties
		var ips []string
		for _, r := range p.IPRules {
			if r.IPAddressOrRange != "" {
				ips = append(ips, r.IPAddressOrRange)
			}
		}
		a := map[string]string{
			"azure_type":                        "cosmosdb_account",
			"engine":                            "cosmosdb",
			"location":                          ca.Location,
			"kind":                              ca.Kind,
			"document_endpoint":                 p.DocumentEndpoint,
			"database_account_offer_type":       p.DatabaseAccountOfferType,
			"public_network_access":             p.PublicNetworkAccess,
			"disable_local_auth":                boolAttr(p.DisableLocalAuth),
			"disable_key_based_metadata_write":  boolAttr(p.DisableKeyBasedMetadataWriteAccess),
			"is_virtual_network_filter_enabled": boolAttr(p.IsVirtualNetworkFilterEnabled),
			"enable_automatic_failover":         boolAttr(p.EnableAutomaticFailover),
			"network_acl_bypass":                p.NetworkACLBypass,
			"minimal_tls_version":               p.MinimalTLSVersion,
			"ip_rules":                          strings.Join(sortedIDs(ips), ","),
			"virtual_network_rules":             strings.Join(sortedIDs(subResourceIDs(p.VirtualNetworkRules)), ","),
		}
		mapTags(a, ca.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: ca.ID, Name: ca.Name, Attributes: pruneEmptyAzure(a)})
		c.runAsEdges(sink, ca.ID, ca.Identity)
	}
	return len(page), nil
}

type sqlServer struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Identity   *azureManagedIdentity `json:"identity"`
	Properties struct {
		AdministratorLogin            string `json:"administratorLogin"`
		Version                       string `json:"version"`
		State                         string `json:"state"`
		FullyQualifiedDomainName      string `json:"fullyQualifiedDomainName"`
		PublicNetworkAccess           string `json:"publicNetworkAccess"`
		MinimalTLSVersion             string `json:"minimalTlsVersion"`
		RestrictOutboundNetworkAccess string `json:"restrictOutboundNetworkAccess"`
		KeyID                         string `json:"keyId"`
		Administrators                *struct {
			Login                     string `json:"login"`
			SID                       string `json:"sid"`
			PrincipalType             string `json:"principalType"`
			AzureADOnlyAuthentication *bool  `json:"azureADOnlyAuthentication"`
		} `json:"administrators"`
		PrivateEndpointConnections []json.RawMessage `json:"privateEndpointConnections"`
	} `json:"properties"`
}

// flexibleServer is the shape PostgreSQL and MySQL flexible servers share; MySQL
// simply leaves authConfig unset.
type flexibleServer struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Location   string                `json:"location"`
	Tags       map[string]string     `json:"tags"`
	Identity   *azureManagedIdentity `json:"identity"`
	Properties struct {
		AdministratorLogin       string `json:"administratorLogin"`
		Version                  string `json:"version"`
		State                    string `json:"state"`
		FullyQualifiedDomainName string `json:"fullyQualifiedDomainName"`
		Network                  *struct {
			PublicNetworkAccess       string `json:"publicNetworkAccess"`
			DelegatedSubnetResourceID string `json:"delegatedSubnetResourceId"`
		} `json:"network"`
		AuthConfig *struct {
			ActiveDirectoryAuth string `json:"activeDirectoryAuth"`
			PasswordAuth        string `json:"passwordAuth"`
		} `json:"authConfig"`
		DataEncryption *struct {
			Type          string `json:"type"`
			PrimaryKeyURI string `json:"primaryKeyURI"`
		} `json:"dataEncryption"`
		HighAvailability *struct {
			Mode string `json:"mode"`
		} `json:"highAvailability"`
		Backup *struct {
			GeoRedundantBackup string `json:"geoRedundantBackup"`
		} `json:"backup"`
		Storage *struct {
			AutoGrow      string `json:"autoGrow"`
			StorageSizeGB int    `json:"storageSizeGB"`
		} `json:"storage"`
	} `json:"properties"`
}

type cosmosAccount struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Location   string                `json:"location"`
	Kind       string                `json:"kind"`
	Tags       map[string]string     `json:"tags"`
	Identity   *azureManagedIdentity `json:"identity"`
	Properties struct {
		DocumentEndpoint                   string `json:"documentEndpoint"`
		DatabaseAccountOfferType           string `json:"databaseAccountOfferType"`
		PublicNetworkAccess                string `json:"publicNetworkAccess"`
		DisableLocalAuth                   *bool  `json:"disableLocalAuth"`
		DisableKeyBasedMetadataWriteAccess *bool  `json:"disableKeyBasedMetadataWriteAccess"`
		IsVirtualNetworkFilterEnabled      *bool  `json:"isVirtualNetworkFilterEnabled"`
		EnableAutomaticFailover            *bool  `json:"enableAutomaticFailover"`
		NetworkACLBypass                   string `json:"networkAclBypass"`
		MinimalTLSVersion                  string `json:"minimalTlsVersion"`
		IPRules                            []struct {
			IPAddressOrRange string `json:"ipAddressOrRange"`
		} `json:"ipRules"`
		VirtualNetworkRules []subResource `json:"virtualNetworkRules"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending budget
// per page and recording evidence and completeness for service at scope. A denied or
// throttled read is a represented gap (returns nil); an unexpected error is surfaced;
// a page is never reported Complete on a failure.
func (c *DatabaseCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(databaseGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(databaseGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(databaseGap(service, scope, collect.Partial, count, "budget exhausted"))
			return nil
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence(service, apiVersion, scope, body))
		var list armList
		if err := json.Unmarshal(body, &list); err != nil {
			_ = sink.Complete(databaseGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(databaseGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(databaseGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *DatabaseCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "database", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: databaseCollectorID},
	}
}

func (c *DatabaseCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return databaseGap(service, scope, status, collected, redact.String(err.Error()))
}

func databaseGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
