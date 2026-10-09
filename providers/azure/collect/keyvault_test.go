package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const vaultID = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1"

// oneVault is a vaults.list page: one premium vault in access-policy authorization
// mode with soft delete, purge protection, a deny-by-default network ruleset, and two
// access policies (deliberately out of object-id order to prove sorting). The vnet
// rule reuses the network collector's subnet id to show the join key lines up.
const oneVault = `{"value":[
	{"id":"` + vaultID + `","name":"kv1","location":"eastus","tags":{"env":"prod"},
	 "properties":{
	   "sku":{"family":"A","name":"premium"},
	   "tenantId":"tenant-1",
	   "vaultUri":"https://kv1.vault.azure.net/",
	   "enableSoftDelete":true,
	   "softDeleteRetentionInDays":90,
	   "enablePurgeProtection":true,
	   "enableRbacAuthorization":false,
	   "enabledForDiskEncryption":true,
	   "publicNetworkAccess":"disabled",
	   "provisioningState":"Succeeded",
	   "networkAcls":{"bypass":"AzureServices","defaultAction":"Deny","ipRules":[{"value":"203.0.113.0/24"}],"virtualNetworkRules":[{"id":"` + subnetID + `"}]},
	   "accessPolicies":[
	     {"objectId":"zzz-principal","tenantId":"tenant-1","permissions":{"keys":["get","list"],"secrets":["get"]}},
	     {"objectId":"aaa-principal","applicationId":"app-1","tenantId":"tenant-1","permissions":{"certificates":["get"],"storage":["get"]}}
	   ]}}
]}`

func keyVaultStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"vaults":          oneVault,
	}}
}

func runKeyVault(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newKeyVaultCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestKeyVaultMapsVault proves a vault becomes a control node keyed by its ARM
// resource id, carrying its security posture and, crucially, its vault URI (the join
// key the storage collector's encryption_keyvault_uri resolves against).
func TestKeyVaultMapsVault(t *testing.T) {
	s := runKeyVault(t, keyVaultStub())

	v, ok := nodeNamed(s, model.NodeControl, vaultID)
	if !ok {
		t.Fatal("kv1 not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "key_vault", "location": "eastus", "sku": "premium", "sku_family": "A",
		"vault_uri": "https://kv1.vault.azure.net/", "tenant_id": "tenant-1",
		"authorization_mode": "access_policies", "soft_delete_enabled": "true",
		"soft_delete_retention_days": "90", "purge_protection": "true",
		"public_network_access": "disabled", "enabled_for_disk_encryption": "true",
		"network_default_action": "Deny", "network_bypass": "AzureServices",
		"network_ip_rules": "203.0.113.0/24", "network_vnet_rules": subnetID,
		"tag:env": "prod",
	} {
		if v.Attributes[k] != want {
			t.Errorf("kv1 %s = %q, want %q", k, v.Attributes[k], want)
		}
	}
	// No secret, key, or certificate value is ever read: only management metadata.
	for _, forbidden := range []string{"key_value", "secret_value", "certificate_value"} {
		if _, bad := v.Attributes[forbidden]; bad {
			t.Errorf("vault must never carry a data-plane %q", forbidden)
		}
	}
	if c := completenessOf(s, "keyvault.vaults"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("keyvault.vaults = %+v, want complete/1", c)
	}
}

// TestKeyVaultAccessPolicies proves the access policies are recorded as sorted
// canonical JSON with the granted principal object ids exposed as forward keys, and no
// authorization verdict is synthesized (that is the identity engine's job).
func TestKeyVaultAccessPolicies(t *testing.T) {
	s := runKeyVault(t, keyVaultStub())
	v, _ := nodeNamed(s, model.NodeControl, vaultID)

	pol := v.Attributes["access_policies"]
	if i, j := strings.Index(pol, "aaa-principal"), strings.Index(pol, "zzz-principal"); i < 0 || j < 0 || i > j {
		t.Errorf("access_policies not sorted by object id: %s", pol)
	}
	if !strings.Contains(pol, `"keys":["get","list"]`) {
		t.Errorf("key permissions not carried: %s", pol)
	}
	// Forward keys join onto the Entra, RBAC, and managed-identity principal nodes.
	if v.Attributes["access_policy_principals"] != "aaa-principal,zzz-principal" {
		t.Errorf("access_policy_principals = %q, want sorted principal ids", v.Attributes["access_policy_principals"])
	}
	for _, forbidden := range []string{"is_public", "over_privileged", "compliant", "effective_access"} {
		if _, bad := v.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
}

// TestKeyVaultRbacMode proves a vault with RBAC authorization enabled records the rbac
// mode (Azure ignores its access policies in that mode, but the collector still
// reports the mode as a fact, never a verdict).
func TestKeyVaultRbacMode(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"vaults":          `{"value":[{"id":"` + vaultID + `","name":"kv1","properties":{"enableRbacAuthorization":true}}]}`,
	}}
	s := runKeyVault(t, api)
	if v, _ := nodeNamed(s, model.NodeControl, vaultID); v.Attributes["authorization_mode"] != "rbac" {
		t.Errorf("authorization_mode = %q, want rbac", v.Attributes["authorization_mode"])
	}
}

// TestKeyVaultDeniedIsGap proves a denied vaults read is a Denied gap (never a pass)
// that does not fail the run and emits no vault node.
func TestKeyVaultDeniedIsGap(t *testing.T) {
	api := keyVaultStub()
	api.failSub = "vaults"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newKeyVaultCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied vaults read must not fail the run: %v", err)
	}
	if statusOf(s, "keyvault.vaults") != collect.Denied {
		t.Errorf("keyvault.vaults = %s, want denied", statusOf(s, "keyvault.vaults"))
	}
	if _, ok := nodeNamed(s, model.NodeControl, vaultID); ok {
		t.Error("a denied read must not emit a vault node")
	}
}

// TestKeyVaultEmptyIsComplete proves an empty subscription is an honest Complete/0.
func TestKeyVaultEmptyIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne, "vaults": `{"value":[]}`}}
	s := runKeyVault(t, api)
	if c := completenessOf(s, "keyvault.vaults"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("keyvault.vaults = %+v, want complete/0", c)
	}
}

// TestKeyVaultPaginates proves nextLink is followed across vault pages.
func TestKeyVaultPaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"vaults?":         `{"value":[{"id":"` + vaultID + `a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":             `{"value":[{"id":"` + vaultID + `b","name":"b"}]}`,
	}}
	s := runKeyVault(t, api)
	if n := nodesByType(s)[model.NodeControl]; n != 2 {
		t.Errorf("vaults across pages = %d, want 2", n)
	}
}

// TestKeyVaultBudgetExhaustion proves the shared budget bounds the sweep.
func TestKeyVaultBudgetExhaustion(t *testing.T) {
	c := newKeyVaultCollector("tenant-1", keyVaultStub())
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "keyvault.vaults"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("keyvault.vaults = %+v, want partial budget-exhausted", got)
	}
}

// TestKeyVaultEvidenceRedactsToken proves the evidence body is scrubbed.
func TestKeyVaultEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"vaults":          `{"value":[{"id":"` + vaultID + `","name":"` + token + `"}]}`,
	}}
	s := runKeyVault(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
