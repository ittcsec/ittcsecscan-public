package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const storageAcctID = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/prodstore"

// twoStorageAccounts is a storageAccounts.list page: one hardened account (public
// blob access off, network default Deny, CMK encryption, HTTPS-only, shared key off)
// and one loose account (public blob access on, network default Allow, platform
// encryption).
const twoStorageAccounts = `{"value":[
	{"id":"` + storageAcctID + `","name":"prodstore","location":"eastus","kind":"StorageV2","sku":{"name":"Standard_LRS"},"tags":{"env":"prod"},
	 "properties":{"provisioningState":"Succeeded","allowBlobPublicAccess":false,"publicNetworkAccess":"Disabled","supportsHttpsTrafficOnly":true,"minimumTlsVersion":"TLS1_2","allowSharedKeyAccess":false,
	  "networkAcls":{"defaultAction":"Deny","ipRules":[{"value":"1.2.3.4"}],"virtualNetworkRules":[{"id":"/subscriptions/sub-1/.../subnets/s1"},{"id":"/subscriptions/sub-1/.../subnets/s2"}]},
	  "encryption":{"keySource":"Microsoft.Keyvault","requireInfrastructureEncryption":true,"keyVaultProperties":{"keyName":"cmk1","keyVaultUri":"https://kv-prod.vault.azure.net/"}},
	  "primaryEndpoints":{"blob":"https://prodstore.blob.core.windows.net/"}}},
	{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/loosestore","name":"loosestore","location":"westus","kind":"StorageV2","sku":{"name":"Standard_GRS"},
	 "properties":{"provisioningState":"Succeeded","allowBlobPublicAccess":true,"publicNetworkAccess":"Enabled","supportsHttpsTrafficOnly":false,
	  "networkAcls":{"defaultAction":"Allow"},
	  "encryption":{"keySource":"Microsoft.Storage"}}}
]}`

func runStorage(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newStorageCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func storageStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"storageAccounts": twoStorageAccounts,
	}}
}

// TestStorageMapsAccounts proves storage accounts become data-store nodes keyed by
// their ARM resource id, with security posture recorded as facts and the CMK Key
// Vault reference kept as an id fact.
func TestStorageMapsAccounts(t *testing.T) {
	s := runStorage(t, storageStub())

	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Fatalf("data-store nodes = %d, want 2", n)
	}
	prod, ok := nodeNamed(s, model.NodeDataStore, storageAcctID)
	if !ok {
		t.Fatal("prodstore not keyed by its ARM resource id")
	}
	for k, v := range map[string]string{
		"azure_type": "storage_account", "location": "eastus", "kind": "StorageV2", "sku": "Standard_LRS",
		"allow_blob_public_access": "false", "public_network_access": "Disabled",
		"https_traffic_only": "true", "minimum_tls_version": "TLS1_2", "allow_shared_key_access": "false",
		"network_default_action": "Deny", "network_ip_rules": "1", "network_vnet_rules": "2",
		"encryption_key_source": "Microsoft.Keyvault", "require_infrastructure_encryption": "true",
		"encryption_keyvault_uri": "https://kv-prod.vault.azure.net/", "encryption_keyvault_key": "cmk1",
		"primary_blob_endpoint": "https://prodstore.blob.core.windows.net/", "tag:env": "prod",
	} {
		if prod.Attributes[k] != v {
			t.Errorf("prodstore %s = %q, want %q", k, prod.Attributes[k], v)
		}
	}

	// The loose account: public blob access on, network default Allow, platform
	// encryption (no CMK key vault fact). All recorded as raw facts, no verdict.
	loose, _ := nodeNamed(s, model.NodeDataStore, "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/loosestore")
	for k, v := range map[string]string{
		"allow_blob_public_access": "true", "public_network_access": "Enabled",
		"https_traffic_only": "false", "network_default_action": "Allow", "encryption_key_source": "Microsoft.Storage",
	} {
		if loose.Attributes[k] != v {
			t.Errorf("loosestore %s = %q, want %q", k, loose.Attributes[k], v)
		}
	}
	if _, ok := loose.Attributes["encryption_keyvault_uri"]; ok {
		t.Error("platform-encrypted account must have no CMK key vault reference")
	}
	// No synthesized public/exposed verdict.
	for _, forbidden := range []string{"is_public", "public", "exposed"} {
		if _, ok := prod.Attributes[forbidden]; ok {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}

	if statusOf(s, "storage.subscriptions") != collect.Complete {
		t.Errorf("storage.subscriptions = %s, want complete", statusOf(s, "storage.subscriptions"))
	}
	if c := completenessOf(s, "storage.accounts"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("storage.accounts = %+v, want complete/2", c)
	}
}

// TestStorageSubscriptionNodeEmitted proves the subscription node is emitted (and
// dedups with the RBAC collector's node of the same id).
func TestStorageSubscriptionNodeEmitted(t *testing.T) {
	s := runStorage(t, storageStub())
	if _, ok := nodeNamed(s, model.NodeSubscription, "sub-1"); !ok {
		t.Error("subscription node not emitted")
	}
}

// TestStorageAccountsDeniedIsGap proves a denied storageAccounts read is a recorded
// Denied gap (never a pass), and the run does not fail; the subscription list still
// completed.
func TestStorageAccountsDeniedIsGap(t *testing.T) {
	api := storageStub()
	api.failSub = "storageAccounts"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newStorageCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied storage read must not fail the run: %v", err)
	}
	if statusOf(s, "storage.accounts") != collect.Denied {
		t.Errorf("storage.accounts = %s, want denied", statusOf(s, "storage.accounts"))
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 0 {
		t.Errorf("data-store nodes = %d, want 0", n)
	}
	if statusOf(s, "storage.subscriptions") != collect.Complete {
		t.Error("subscription list should still complete when the accounts read is denied")
	}
}

// TestStorageSubscriptionsDeniedIsGap proves a denied subscription list is a Denied
// gap with no accounts read.
func TestStorageSubscriptionsDeniedIsGap(t *testing.T) {
	api := &stubARM{failSub: "/subscriptions?", failWith: &azureError{status: 403, body: "AuthorizationFailed"}}
	var s collect.Scan
	if err := newStorageCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("denied subscriptions must not fail the run: %v", err)
	}
	if statusOf(s, "storage.subscriptions") != collect.Denied {
		t.Errorf("storage.subscriptions = %s, want denied", statusOf(s, "storage.subscriptions"))
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 0 {
		t.Errorf("data-store nodes = %d, want 0", n)
	}
}

// TestStorageNoAccountsIsComplete proves an empty subscription is an honest
// Complete/0, not a gap.
func TestStorageNoAccountsIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne, "storageAccounts": `{"value":[]}`}}
	s := runStorage(t, api)
	if c := completenessOf(s, "storage.accounts"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("storage.accounts = %+v, want complete/0", c)
	}
}

// TestStoragePaginates proves nextLink is followed across account pages.
func TestStoragePaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":  subsOne,
		"storageAccounts?": `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":              `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/b","name":"b"}]}`,
	}}
	s := runStorage(t, api)
	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Errorf("accounts across pages = %d, want 2", n)
	}
	if c := completenessOf(s, "storage.accounts"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("storage.accounts = %+v, want complete/2", c)
	}
}

// TestStorageBudgetExhaustion proves the shared budget bounds the sweep: with budget
// only for the subscription list, the accounts pass is a Partial "budget exhausted".
func TestStorageBudgetExhaustion(t *testing.T) {
	api := storageStub()
	c := newStorageCollector("tenant-1", api)
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "storage.accounts"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("storage.accounts = %+v, want partial budget-exhausted", got)
	}
}

// TestStorageEvidenceRedactsToken proves the evidence body is scrubbed.
func TestStorageEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"storageAccounts": `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/x","name":"` + token + `"}]}`,
	}}
	s := runStorage(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
