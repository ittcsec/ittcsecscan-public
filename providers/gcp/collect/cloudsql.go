package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// cloudSQLCollectorID is the stable id this collector is credited with.
const cloudSQLCollectorID = "collector:gcp.cloudsql.instances"

const (
	// cloudSQLBaseURL is the Cloud SQL Admin API v1 endpoint. The collector only
	// ever issues the read-only instances.list GET; it never reads a database's
	// contents, connection credentials, or the generated server or client
	// certificates (those are separate resources this never touches).
	cloudSQLBaseURL = "https://sqladmin.googleapis.com/v1"
	// cloudSQLAPIVersion is recorded as evidence provenance.
	cloudSQLAPIVersion = "v1"
)

// CloudSQLCollector reads a GCP project's Cloud SQL instances, the GCP counterpart of
// the AWS RDS and Azure database collectors. The read was verified against the Cloud
// SQL Admin API reference (v1, 2026-09-22): projects.instances.list is a read-only
// GET, paginated by pageToken/nextPageToken, requiring cloudsql.instances.list, and
// it returns instance metadata only (no database content, connection credential, or
// certificate). instances.list is a project-global call that returns instances across
// every region (each carries its region), so like Cloud Storage this is the
// global-list case and does not fan out over a region set.
//
// Each instance becomes a data-store node keyed by its full resource name (ADR-0019
// §2). Its customer-managed encryption key is recorded as a forward-key fact so it
// joins the Cloud KMS node, and its private-network self-link so it joins the VPC
// node. The instance's service agent (serviceAccountEmailAddress) is emitted as a
// run-as assumes edge to a workload node keyed by that email, exactly as the compute
// collector does for a VM's attached service accounts, so the paths that identity
// reaches (for example the CMK) resolve. Per ADR-0019 §3 no "is public" verdict is
// synthesized: the public-IP flag, SSL mode, and authorized networks are raw facts.
type CloudSQLCollector struct {
	projectID string
	api       gcpAPI
	budget    *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewCloudSQLCollector builds the collector with a REST client that authenticates
// with a token from the adapter's resolved credential (ADR-0018 §3).
func NewCloudSQLCollector(projectID string, tokens oauth2.TokenSource, budget *collect.Budget) *CloudSQLCollector {
	return &CloudSQLCollector{projectID: projectID, api: &gcpClient{tokens: tokens, http: sharedHTTPClient}, budget: budget}
}

// newCloudSQLCollector is the injectable constructor tests use with a stub API.
func newCloudSQLCollector(projectID string, api gcpAPI) *CloudSQLCollector {
	return &CloudSQLCollector{projectID: projectID, api: api}
}

func (c *CloudSQLCollector) ID() string               { return cloudSQLCollectorID }
func (c *CloudSQLCollector) Provider() model.Provider { return model.GCP }

func cloudSQLRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GCP, Profile: permissions.Discovery, Permission: "cloudsql.instances.list", By: cloudSQLCollectorID},
	}
}

func init() {
	for _, r := range cloudSQLRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *CloudSQLCollector) Requirements() []permissions.Requirement { return cloudSQLRequirements() }

// Collect lists the project's Cloud SQL instances, emitting one data-store node each
// with its security configuration, a run-as edge to its service agent, and one
// completeness record (cloudsql.instances). An empty project is an honest Complete/0;
// a disabled API is Unsupported; a denied or throttled read is a represented gap.
func (c *CloudSQLCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "cloudsql.instances"
	if c.projectID == "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Unsupported, Reason: "the credential has no associated default project to scope to"})
	}
	base := fmt.Sprintf("%s/projects/%s/instances", cloudSQLBaseURL, url.PathEscape(c.projectID))
	pageToken := ""
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "page limit reached"})
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
			return nil
		}
		u := base
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		body, err := c.api.get(ctx, u)
		if err != nil {
			_ = sink.Complete(c.completeness(service, count, err))
			if isDenied(err) || isThrottle(err) || isServiceDisabled(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence("instances.list", body))
		var pg sqlInstanceListPage
		if err := json.Unmarshal(body, &pg); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, in := range pg.Items {
			c.emitInstance(sink, in)
			count++
		}
		if pg.NextPageToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: count})
			return nil
		}
		pageToken = pg.NextPageToken
	}
}

func (c *CloudSQLCollector) emitInstance(sink collect.Sink, in sqlInstance) {
	if in.Name == "" {
		return
	}
	a := map[string]string{
		"region":           in.Region,
		"database_version": in.DatabaseVersion,
		"state":            in.State,
		"connection_name":  in.ConnectionName,
		"service_account":  in.ServiceAccountEmailAddress,
	}
	if in.DiskEncryptionConfiguration != nil && in.DiskEncryptionConfiguration.KmsKeyName != "" {
		// Forward key: joins the Cloud KMS crypto-key node.
		a["cmk_key"] = in.DiskEncryptionConfiguration.KmsKeyName
		a["customer_managed_encryption"] = "true"
	} else {
		a["customer_managed_encryption"] = "false"
	}
	if s := in.Settings; s != nil {
		if ip := s.IPConfiguration; ip != nil {
			a["public_ip_enabled"] = boolStr(ip.IPv4Enabled)
			a["ssl_mode"] = ip.SSLMode
			if ip.RequireSSL != nil {
				a["require_ssl"] = boolStr(*ip.RequireSSL)
			}
			if ip.PrivateNetwork != "" {
				// Forward key: joins the VPC network node.
				a["private_network"] = ip.PrivateNetwork
			}
			var nets []string
			for _, an := range ip.AuthorizedNetworks {
				if an.Value != "" {
					nets = append(nets, an.Value)
				}
			}
			if len(nets) > 0 {
				a["authorized_networks"] = joinSortedGCS(nets)
			}
		}
		if b := s.BackupConfiguration; b != nil {
			a["backup_enabled"] = boolStr(b.Enabled)
			a["point_in_time_recovery"] = boolStr(b.PointInTimeRecoveryEnabled)
		}
		a["storage_auto_resize"] = boolStr(s.StorageAutoResize != nil && *s.StorageAutoResize)
		a["deletion_protection"] = boolStr(s.DeletionProtectionEnabled)
		a["data_disk_type"] = s.DataDiskType
	}
	for k, v := range a {
		if v == "" {
			delete(a, k)
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: sqlInstanceResourceName(c.projectID, in.Name), Name: in.Name, Attributes: a})

	// Run-as edge to the instance's service agent, keyed by email so it dedups with
	// the service-account identity nodes, mirroring the compute collector.
	if in.ServiceAccountEmailAddress != "" {
		_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: in.ServiceAccountEmailAddress, Attributes: attrs("kind", "cloudsql_service_agent")})
		_ = sink.Link(collect.Link{SourceNativeID: sqlInstanceResourceName(c.projectID, in.Name), TargetNativeID: in.ServiceAccountEmailAddress, Kind: model.EdgeAssumes})
	}
}

// sqlInstanceResourceName is the instance's full (asset-inventory) resource name, the
// canonical id this node is keyed by (ADR-0019 §2).
func sqlInstanceResourceName(project, name string) string {
	return "//cloudsql.googleapis.com/projects/" + project + "/instances/" + name
}

type sqlInstanceListPage struct {
	Items         []sqlInstance `json:"items"`
	NextPageToken string        `json:"nextPageToken"`
}

// sqlInstance is the subset of the DatabaseInstance resource the collector reads
// (verified against the Cloud SQL Admin API reference, v1, 2026-09-22). No database
// content, credential, or certificate is read.
type sqlInstance struct {
	Name                        string `json:"name"`
	Region                      string `json:"region"`
	DatabaseVersion             string `json:"databaseVersion"`
	State                       string `json:"state"`
	ConnectionName              string `json:"connectionName"`
	ServiceAccountEmailAddress  string `json:"serviceAccountEmailAddress"`
	DiskEncryptionConfiguration *struct {
		KmsKeyName string `json:"kmsKeyName"`
	} `json:"diskEncryptionConfiguration"`
	Settings *struct {
		DataDiskType              string `json:"dataDiskType"`
		StorageAutoResize         *bool  `json:"storageAutoResize"`
		DeletionProtectionEnabled bool   `json:"deletionProtectionEnabled"`
		IPConfiguration           *struct {
			IPv4Enabled        bool   `json:"ipv4Enabled"`
			RequireSSL         *bool  `json:"requireSsl"`
			SSLMode            string `json:"sslMode"`
			PrivateNetwork     string `json:"privateNetwork"`
			AuthorizedNetworks []struct {
				Value string `json:"value"`
				Name  string `json:"name"`
			} `json:"authorizedNetworks"`
		} `json:"ipConfiguration"`
		BackupConfiguration *struct {
			Enabled                    bool `json:"enabled"`
			PointInTimeRecoveryEnabled bool `json:"pointInTimeRecoveryEnabled"`
		} `json:"backupConfiguration"`
	} `json:"settings"`
}

func (c *CloudSQLCollector) scope() collect.Scope { return collect.Scope{Account: c.projectID} }

func (c *CloudSQLCollector) evidence(operation string, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GCP, Service: "cloudsql", Operation: operation, Region: collect.Global,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: cloudSQLAPIVersion, Collector: cloudSQLCollectorID},
	}
}

func (c *CloudSQLCollector) completeness(service string, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isServiceDisabled(err):
		status = collect.Unsupported
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: collected, Reason: redact.String(err.Error())}
}
