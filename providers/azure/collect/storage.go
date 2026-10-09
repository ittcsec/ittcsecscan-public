package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// storageCollectorID is the stable id this collector is credited with.
const storageCollectorID = "collector:azure.storage.accounts"

// storageAPIVersion is the doc-verified Storage Resource Provider API version
// (2026-09-21). The List operation returns each account's full security posture and
// no key material (keys need the separate ListKeys operation, which this collector
// never calls).
const storageAPIVersion = "2026-06-01"

// StorageCollector reads the tenant's Azure Storage accounts and their
// security-relevant configuration (public blob access, network rules, encryption
// including customer-managed keys, transport security, and shared-key access), the
// first Azure sensitive-asset collector and the direct counterpart of the AWS S3 and
// GCP GCS collectors. Storage accounts live on the Resource Manager plane and are
// subscription-scoped, so the collector enumerates the accessible subscriptions and
// reads each one's accounts in a single paginated list (the list carries the full
// properties, so there is no per-account fan-out).
//
// It records the provider's own facts and does not synthesize an "is public"
// verdict: that belongs to the rule and reachability engines. Per ADR-0019 §3 it
// emits nodes and attributes only, no edges; the customer-managed-key Key Vault
// reference is recorded as an id fact so a future Key Vault collector's nodes join
// onto it, the same forward-keying the RDS and CloudTrail collectors use for KMS.
// The read was verified against the Azure Storage REST reference (2026-09-21): a
// read-only GET, paginated by nextLink, returning no secret value.
type StorageCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewStorageCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewStorageCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *StorageCollector {
	return &StorageCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newStorageCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newStorageCollector(tenantID string, api armAPI) *StorageCollector {
	return &StorageCollector{tenantID: tenantID, api: api}
}

func (c *StorageCollector) ID() string               { return storageCollectorID }
func (c *StorageCollector) Provider() model.Provider { return model.Azure }

func storageRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Azure, Profile: permissions.Discovery, Permission: "Microsoft.Storage/storageAccounts/read", By: storageCollectorID},
	}
}

func init() {
	for _, r := range storageRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *StorageCollector) Requirements() []permissions.Requirement { return storageRequirements() }

// Collect enumerates the accessible subscriptions and, for each, lists its storage
// accounts and maps each to a data-store node. Two completeness records are
// produced: storage.subscriptions (the subscription list) and storage.accounts (per
// subscription). Storage is a global management-plane read, so there is one region:
// "global"; each account's Azure location is recorded as an attribute.
func (c *StorageCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "storage.subscriptions", tenantScope, subscriptionsAPIVersion,
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
		// The subscription node dedups with the RBAC collector's node of the same id.
		_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: sub.SubscriptionID, Name: sub.DisplayName,
			Attributes: attrs("state", sub.State)})
		scope := collect.Scope{Account: c.tenantID, Resource: sub.SubscriptionID}
		_ = c.pageThrough(ctx, sink, "storage.accounts", scope, storageAPIVersion,
			fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=%s", armBaseURL, sub.SubscriptionID, storageAPIVersion),
			func(raw json.RawMessage) (int, error) {
				var page []storageAccount
				if err := json.Unmarshal(raw, &page); err != nil {
					return 0, err
				}
				for _, sa := range page {
					c.mapAccount(sink, sa)
				}
				return len(page), nil
			})
	}
	return nil
}

// mapAccount emits one data-store node per storage account (keyed by its ARM
// resource id) with its security posture recorded as raw facts.
func (c *StorageCollector) mapAccount(sink collect.Sink, sa storageAccount) {
	if sa.ID == "" {
		return
	}
	p := sa.Properties
	a := map[string]string{
		"azure_type":               "storage_account",
		"location":                 sa.Location,
		"kind":                     sa.Kind,
		"sku":                      sa.Sku.Name,
		"provisioning_state":       p.ProvisioningState,
		"allow_blob_public_access": boolAttr(p.AllowBlobPublicAccess),
		"public_network_access":    p.PublicNetworkAccess,
		"https_traffic_only":       boolAttr(p.SupportsHTTPSTrafficOnly),
		"minimum_tls_version":      p.MinimumTLSVersion,
		"allow_shared_key_access":  boolAttr(p.AllowSharedKeyAccess),
	}
	if n := p.NetworkACLs; n != nil {
		a["network_default_action"] = n.DefaultAction
		a["network_ip_rules"] = strconv.Itoa(len(n.IPRules))
		a["network_vnet_rules"] = strconv.Itoa(len(n.VirtualNetworkRules))
	}
	if e := p.Encryption; e != nil {
		a["encryption_key_source"] = e.KeySource
		a["require_infrastructure_encryption"] = boolAttr(e.RequireInfrastructureEncryption)
		if kv := e.KeyVaultProperties; kv != nil {
			// The customer-managed-key reference, recorded as an id fact so a future
			// Key Vault collector's node joins onto it.
			a["encryption_keyvault_uri"] = kv.KeyVaultURI
			a["encryption_keyvault_key"] = kv.KeyName
		}
	}
	if ep := p.PrimaryEndpoints; ep != nil {
		a["primary_blob_endpoint"] = ep.Blob
	}
	for k, v := range sa.Tags {
		if k != "" {
			a["tag:"+k] = v
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: sa.ID, Name: sa.Name, Attributes: pruneEmptyAzure(a)})
}

// storageAccount is the subset of the StorageAccount resource the collector reads
// (verified against the Storage REST reference, 2026-09-21). Go's JSON decoder
// matches field names case-insensitively, so the historical lower-case casings
// (keyvaultproperties, keyvaulturi) match these tags too.
type storageAccount struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Location string            `json:"location"`
	Kind     string            `json:"kind"`
	Tags     map[string]string `json:"tags"`
	Sku      struct {
		Name string `json:"name"`
	} `json:"sku"`
	Properties struct {
		ProvisioningState        string `json:"provisioningState"`
		AllowBlobPublicAccess    *bool  `json:"allowBlobPublicAccess"`
		PublicNetworkAccess      string `json:"publicNetworkAccess"`
		SupportsHTTPSTrafficOnly *bool  `json:"supportsHttpsTrafficOnly"`
		MinimumTLSVersion        string `json:"minimumTlsVersion"`
		AllowSharedKeyAccess     *bool  `json:"allowSharedKeyAccess"`
		NetworkACLs              *struct {
			DefaultAction       string            `json:"defaultAction"`
			IPRules             []json.RawMessage `json:"ipRules"`
			VirtualNetworkRules []json.RawMessage `json:"virtualNetworkRules"`
		} `json:"networkAcls"`
		Encryption *struct {
			KeySource                       string `json:"keySource"`
			RequireInfrastructureEncryption *bool  `json:"requireInfrastructureEncryption"`
			KeyVaultProperties              *struct {
				KeyName     string `json:"keyName"`
				KeyVaultURI string `json:"keyVaultUri"`
			} `json:"keyVaultProperties"`
		} `json:"encryption"`
		PrimaryEndpoints *struct {
			Blob string `json:"blob"`
		} `json:"primaryEndpoints"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending
// budget per page and recording evidence and completeness for service at scope. A
// denied or throttled read is a represented gap (returns nil); an unexpected error
// is surfaced; a page is never reported Complete on a failure.
func (c *StorageCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(storageGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(storageGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(storageGap(service, scope, collect.Partial, count, "budget exhausted"))
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
			_ = sink.Complete(storageGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(storageGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(storageGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *StorageCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "storage", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: storageCollectorID},
	}
}

func (c *StorageCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return storageGap(service, scope, status, collected, redact.String(err.Error()))
}

func storageGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}

// pruneEmptyAzure drops empty-valued attributes, returning nil when none remain.
func pruneEmptyAzure(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
