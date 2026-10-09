package pack

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
	"github.com/ittcsec/ittcsecscan/internal/rules"
	"github.com/ittcsec/ittcsecscan/packs"
)

//go:embed testdata/pack_aws_complete.json testdata/pack_aws_denied.json testdata/pack_gcp.json testdata/pack_azure.json testdata/pack_keymgmt.json
var goldenFS embed.FS

type keyer struct{}

func (keyer) StableID(nativeID string) (model.StableID, error) {
	sum := sha256.Sum256([]byte(nativeID))
	return model.StableID(hex.EncodeToString(sum[:])), nil
}

// nrm normalizes a builtin-test collect.Scan fixture into the model graph the
// engine now reads, so the existing fixtures drive the re-targeted engine.
func nrm(scan *collect.Scan) *normalize.NormalizedScan {
	g, err := normalize.Normalize(*scan, keyer{}, normalize.Meta{})
	if err != nil {
		panic(err)
	}
	return &g
}

// TestPackReTargetReproducesGolden proves the re-targeted engine reproduces, for
// the real built-in core-p0 rules across all three clouds and the honest-unknown
// path, byte-for-byte the findings the pre-re-target engine produced (captured in
// the preceding commit from the collect.Scan-based engine). Same findings, same
// fixtures, before and after the re-target.
func TestPackReTargetReproducesGolden(t *testing.T) {
	// This golden pins the re-targeted engine's output for the core-p0 rules only, so it loads
	// just that pack. Other embedded packs (ai-guard, identity-hygiene) have their own tests and
	// must not perturb these core-p0 fixtures.
	pk, err := LoadBuiltin(packs.FS, "core-p0")
	if err != nil {
		t.Fatal(err)
	}
	all := pk.Rules
	for name, scan := range packGoldenFixtures() {
		want, err := goldenFS.ReadFile("testdata/" + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rs, err := rules.Evaluate(nrm(scan), all)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := json.MarshalIndent(rs, "", "  ")
		got = append(got, '\n')
		if string(got) != string(want) {
			t.Errorf("%s: re-targeted findings differ from the pre-re-target golden\n--- got ---\n%s", name, got)
		}
	}
}

func packGoldenFixtures() map[string]*collect.Scan {
	gcp := &collect.Scan{
		Nodes: []collect.Node{
			ds("//storage.googleapis.com/projects/_/buckets/pub", map[string]string{"storage_class": "STANDARD", "iam_all_users_roles": "roles/storage.objectViewer"}),
			ds("//storage.googleapis.com/projects/_/buckets/priv", map[string]string{"storage_class": "STANDARD"}),
			ds("//cloudsql.googleapis.com/projects/p/instances/open", map[string]string{"public_ip_enabled": "true", "authorized_networks": "0.0.0.0/0"}),
			ds("//cloudsql.googleapis.com/projects/p/instances/scoped", map[string]string{"public_ip_enabled": "true", "authorized_networks": "203.0.113.0/24"}),
		},
		Completeness: []collect.Completeness{
			{Service: "storage.buckets", Status: collect.Complete},
			{Service: "storage.bucketIam", Status: collect.Complete},
			{Service: "cloudsql.instances", Status: collect.Complete},
		},
	}
	azure := &collect.Scan{
		Nodes: []collect.Node{
			ds("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/pub", map[string]string{"azure_type": "storage_account", "allow_blob_public_access": "true"}),
			ds("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/priv", map[string]string{"azure_type": "storage_account", "allow_blob_public_access": "false"}),
			ds("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/pub", map[string]string{"engine": "sql", "public_network_access": "Enabled"}),
		},
		Completeness: []collect.Completeness{
			{Service: "storage.accounts", Status: collect.Complete},
			{Service: "database.sqlServers", Status: collect.Complete},
			{Service: "database.postgresqlServers", Status: collect.Complete},
			{Service: "database.mysqlServers", Status: collect.Complete},
			{Service: "database.cosmosAccounts", Status: collect.Complete},
		},
	}
	kms := &collect.Scan{
		Nodes: []collect.Node{
			ctrl("arn:aws:kms:us-east-1:1:key/norot", map[string]string{"rotation_enabled": "false"}),
			ctrl("arn:aws:kms:us-east-1:1:key/rot", map[string]string{"rotation_enabled": "true"}),
			ctrl("//cloudkms.googleapis.com/projects/p/.../k", map[string]string{"rotation_configured": "false"}),
			ctrl("/subscriptions/s/.../vaults/nopurge", map[string]string{"azure_type": "key_vault"}),
			ctrl("/subscriptions/s/.../vaults/purge", map[string]string{"azure_type": "key_vault", "purge_protection": "true"}),
		},
		Completeness: []collect.Completeness{
			{Service: "kms.keyDetails", Status: collect.Complete},
			{Service: "cloudkms.cryptoKeys", Status: collect.Complete},
			{Service: "keyvault.vaults", Status: collect.Complete},
		},
	}
	return map[string]*collect.Scan{
		"pack_aws_complete": awsScan(collect.Complete),
		"pack_aws_denied":   awsScan(collect.Denied),
		"pack_gcp":          gcp,
		"pack_azure":        azure,
		"pack_keymgmt":      kms,
	}
}
