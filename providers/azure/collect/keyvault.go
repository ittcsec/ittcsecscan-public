package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// keyVaultCollectorID is the stable id this collector is credited with.
const keyVaultCollectorID = "collector:azure.keyvault"

// keyVaultAPIVersion is the doc-verified Key Vault management API version
// (2026-09-21, latest stable GA). The list operation returns vault metadata only and
// never a key, secret, or certificate value.
const keyVaultAPIVersion = "2024-11-01"

// KeyVaultCollector reads the tenant's Azure key vaults, the Azure counterpart of the
// AWS KMS collector: the key-management control plane. It reads management-plane vault
// metadata only (SKU, authorization mode, soft-delete and purge protection, network
// ACLs, and access policies) and never the data plane, so no key, secret, or
// certificate value is retrieved (invariant: never retrieve secret values). Vaults
// live on the Resource Manager plane and are subscription-scoped, so the collector
// enumerates the accessible subscriptions and lists vaults in each.
//
// Per ADR-0019 §3 it emits nodes and attributes only. A vault becomes a control node
// keyed by its ARM resource id, carrying its vault URI so the storage collector's
// customer-managed-key reference (encryption_keyvault_uri) joins onto it. Access
// policies are recorded as a sorted canonical-JSON fact plus a principal-id list, the
// same shape the network collector uses for NSG rules: the object ids are forward
// keys that join onto the Entra, RBAC, and managed-identity principal nodes, with no
// synthesized authorization verdict (that is the identity engine's output). The
// authorization mode (RBAC or access policies) is recorded as a fact so a downstream
// consumer knows which governs, never collapsed into a pass or fail.
type KeyVaultCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewKeyVaultCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewKeyVaultCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *KeyVaultCollector {
	return &KeyVaultCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newKeyVaultCollector is the injectable constructor tests use with a stub API.
func newKeyVaultCollector(tenantID string, api armAPI) *KeyVaultCollector {
	return &KeyVaultCollector{tenantID: tenantID, api: api}
}

func (c *KeyVaultCollector) ID() string               { return keyVaultCollectorID }
func (c *KeyVaultCollector) Provider() model.Provider { return model.Azure }

func keyVaultRequirements() []permissions.Requirement {
	return []permissions.Requirement{{
		Provider: model.Azure, Profile: permissions.Discovery,
		Permission: "Microsoft.KeyVault/vaults/read", By: keyVaultCollectorID,
	}}
}

func init() {
	for _, r := range keyVaultRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permission the collector needs.
func (c *KeyVaultCollector) Requirements() []permissions.Requirement { return keyVaultRequirements() }

// Collect enumerates the accessible subscriptions and lists key vaults in each. One
// completeness record is produced per subscription for keyvault.vaults, plus
// keyvault.subscriptions.
func (c *KeyVaultCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "keyvault.subscriptions", tenantScope, subscriptionsAPIVersion,
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
		_ = c.pageThrough(ctx, sink, "keyvault.vaults", scope, keyVaultAPIVersion,
			fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=%s", armBaseURL, sub.SubscriptionID, keyVaultAPIVersion),
			func(raw json.RawMessage) (int, error) { return c.decodeVaults(sink, raw) })
	}
	return nil
}

func (c *KeyVaultCollector) decodeVaults(sink collect.Sink, raw json.RawMessage) (int, error) {
	var page []vault
	if err := json.Unmarshal(raw, &page); err != nil {
		return 0, err
	}
	for _, v := range page {
		if v.ID == "" {
			continue
		}
		p := v.Properties
		a := map[string]string{
			"azure_type":                      "key_vault",
			"location":                        v.Location,
			"sku":                             p.Sku.Name,
			"sku_family":                      p.Sku.Family,
			"vault_uri":                       p.VaultURI,
			"tenant_id":                       p.TenantID,
			"authorization_mode":              authorizationMode(p.EnableRbacAuthorization),
			"soft_delete_enabled":             boolAttr(p.EnableSoftDelete),
			"purge_protection":                boolAttr(p.EnablePurgeProtection),
			"public_network_access":           p.PublicNetworkAccess,
			"provisioning_state":              p.ProvisioningState,
			"private_endpoint_count":          strconv.Itoa(len(p.PrivateEndpointConnections)),
			"enabled_for_deployment":          boolAttr(p.EnabledForDeployment),
			"enabled_for_disk_encryption":     boolAttr(p.EnabledForDiskEncryption),
			"enabled_for_template_deployment": boolAttr(p.EnabledForTemplateDeployment),
		}
		if p.SoftDeleteRetentionInDays != nil {
			a["soft_delete_retention_days"] = strconv.Itoa(*p.SoftDeleteRetentionInDays)
		}
		if n := p.NetworkACLs; n != nil {
			a["network_default_action"] = n.DefaultAction
			a["network_bypass"] = n.Bypass
			var ips []string
			for _, r := range n.IPRules {
				if r.Value != "" {
					ips = append(ips, r.Value)
				}
			}
			a["network_ip_rules"] = strings.Join(sortedIDs(ips), ",")
			a["network_vnet_rules"] = strings.Join(sortedIDs(subResourceIDs(n.VirtualNetworkRules)), ",")
		}
		policies := make([]kvAccessPolicy, 0, len(p.AccessPolicies))
		principals := make([]string, 0, len(p.AccessPolicies))
		for _, ap := range p.AccessPolicies {
			policies = append(policies, kvAccessPolicy{
				ObjectID: ap.ObjectID, ApplicationID: ap.ApplicationID, TenantID: ap.TenantID,
				Keys: ap.Permissions.Keys, Secrets: ap.Permissions.Secrets,
				Certificates: ap.Permissions.Certificates, Storage: ap.Permissions.Storage,
			})
			if ap.ObjectID != "" {
				principals = append(principals, ap.ObjectID)
			}
		}
		sort.Slice(policies, func(i, j int) bool { return policies[i].ObjectID < policies[j].ObjectID })
		if len(policies) > 0 {
			a["access_policies"] = canonicalJSON(policies)
			// Forward keys: the granted principal object ids join onto the Entra, RBAC,
			// and managed-identity principal nodes.
			a["access_policy_principals"] = strings.Join(sortedIDs(principals), ",")
		}
		mapTags(a, v.Tags)
		_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: v.ID, Name: v.Name, Attributes: pruneEmptyAzure(a)})
	}
	return len(page), nil
}

// authorizationMode names which authorization plane governs the vault's data actions.
// When RBAC is enabled Azure ignores the access policies; the mode is recorded so a
// downstream consumer knows which one is in effect, without a synthesized verdict.
func authorizationMode(rbac *bool) string {
	if rbac != nil && *rbac {
		return "rbac"
	}
	return "access_policies"
}

// kvAccessPolicy is one vault access policy entry as reported: a principal object id
// and the data-plane permission sets it is granted.
type kvAccessPolicy struct {
	ObjectID      string   `json:"object_id"`
	ApplicationID string   `json:"application_id,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	Keys          []string `json:"keys,omitempty"`
	Secrets       []string `json:"secrets,omitempty"`
	Certificates  []string `json:"certificates,omitempty"`
	Storage       []string `json:"storage,omitempty"`
}

type vault struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		Sku struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		} `json:"sku"`
		TenantID                     string `json:"tenantId"`
		VaultURI                     string `json:"vaultUri"`
		EnableRbacAuthorization      *bool  `json:"enableRbacAuthorization"`
		EnableSoftDelete             *bool  `json:"enableSoftDelete"`
		SoftDeleteRetentionInDays    *int   `json:"softDeleteRetentionInDays"`
		EnablePurgeProtection        *bool  `json:"enablePurgeProtection"`
		EnabledForDeployment         *bool  `json:"enabledForDeployment"`
		EnabledForDiskEncryption     *bool  `json:"enabledForDiskEncryption"`
		EnabledForTemplateDeployment *bool  `json:"enabledForTemplateDeployment"`
		PublicNetworkAccess          string `json:"publicNetworkAccess"`
		ProvisioningState            string `json:"provisioningState"`
		NetworkACLs                  *struct {
			Bypass        string `json:"bypass"`
			DefaultAction string `json:"defaultAction"`
			IPRules       []struct {
				Value string `json:"value"`
			} `json:"ipRules"`
			VirtualNetworkRules []subResource `json:"virtualNetworkRules"`
		} `json:"networkAcls"`
		AccessPolicies []struct {
			ApplicationID string `json:"applicationId"`
			ObjectID      string `json:"objectId"`
			TenantID      string `json:"tenantId"`
			Permissions   struct {
				Keys         []string `json:"keys"`
				Secrets      []string `json:"secrets"`
				Certificates []string `json:"certificates"`
				Storage      []string `json:"storage"`
			} `json:"permissions"`
		} `json:"accessPolicies"`
		PrivateEndpointConnections []json.RawMessage `json:"privateEndpointConnections"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending budget
// per page and recording evidence and completeness for service at scope. A denied or
// throttled read is a represented gap (returns nil); an unexpected error is surfaced;
// a page is never reported Complete on a failure.
func (c *KeyVaultCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(keyVaultGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(keyVaultGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(keyVaultGap(service, scope, collect.Partial, count, "budget exhausted"))
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
			_ = sink.Complete(keyVaultGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(keyVaultGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(keyVaultGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *KeyVaultCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "keyvault", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: keyVaultCollectorID},
	}
}

func (c *KeyVaultCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return keyVaultGap(service, scope, status, collected, redact.String(err.Error()))
}

func keyVaultGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
