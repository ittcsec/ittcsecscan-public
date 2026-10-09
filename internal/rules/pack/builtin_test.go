package pack

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules"
	"github.com/ittcsec/ittcsecscan/packs"
)

func stateFor(rs []rules.Result, ruleID, entityID string) model.Outcome {
	for _, r := range rs {
		if r.Rule.RuleID == ruleID && r.EntityID == entityID {
			return r.State
		}
	}
	return ""
}

// TestBuiltinPacksLoadAndValidate proves every shipped built-in rule parses and passes
// validation (its vocabulary and structure are real), so a malformed built-in rule is a
// build-time failure.
func TestBuiltinPacksLoadAndValidate(t *testing.T) {
	all, err := LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("loading built-in packs: %v", err)
	}
	if len(all) < 9 {
		t.Fatalf("expected at least the 9 exposure and key-management rules, got %d", len(all))
	}
	for _, r := range all {
		if err := r.Validate(); err != nil {
			t.Errorf("built-in rule %s failed validation: %v", r.ID, err)
		}
	}
}

func ds(id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: model.NodeDataStore, NativeID: id, Attributes: attrs}
}

// awsScan builds a single-cloud AWS scan with a public and a private S3 bucket and a
// public RDS instance. Only AWS completeness records exist; the other clouds' services
// are absent, as on a real single-provider scan.
func awsScan(bucketConfig collect.Status) *collect.Scan {
	return &collect.Scan{
		Nodes: []collect.Node{
			ds("arn:aws:s3:::pub", map[string]string{"policy_is_public": "true", "region": "us-east-1"}),
			ds("arn:aws:s3:::priv", map[string]string{"policy_is_public": "false", "region": "us-east-1"}),
			ds("arn:aws:rds:us-east-1:1:db:pubdb", map[string]string{"engine": "postgres", "publicly_accessible": "true"}),
		},
		Completeness: []collect.Completeness{
			{Service: "s3.buckets", Status: collect.Complete},
			{Service: "s3.bucketConfig", Status: bucketConfig},
			{Service: "rds.dbInstances", Status: collect.Complete},
		},
	}
}

// TestExposureAWS proves the AWS exposure rules fire correctly on a complete AWS scan
// and that the other clouds' rules are not-applicable (their evidence was not collected).
func TestExposureAWS(t *testing.T) {
	all, _ := LoadBuiltinAll(packs.FS, nil)
	rs, err := rules.Evaluate(nrm(awsScan(collect.Complete)), all)
	if err != nil {
		t.Fatal(err)
	}
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::pub"); s != model.Fail {
		t.Errorf("public bucket = %s, want fail", s)
	}
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::priv"); s != model.Pass {
		t.Errorf("private bucket = %s, want pass", s)
	}
	if s := stateFor(rs, "CORE-P0-DATABASE-PUBLIC-AWS", "arn:aws:rds:us-east-1:1:db:pubdb"); s != model.Fail {
		t.Errorf("public rds = %s, want fail", s)
	}
	// The S3 rule must not have selected the RDS node (selector fact_absent engine).
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:rds:us-east-1:1:db:pubdb"); s != "" {
		t.Errorf("storage rule wrongly evaluated the RDS node (state %s)", s)
	}
	// Other clouds' rules are not-applicable (evidence absent), never a false pass.
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-GCP", ""); s != model.NotApplicable {
		t.Errorf("GCP storage rule on an AWS scan = %s, want not_applicable", s)
	}
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AZURE", ""); s != model.NotApplicable {
		t.Errorf("Azure storage rule on an AWS scan = %s, want not_applicable", s)
	}
}

// TestExposureHonestUnknown proves that when the deciding evidence (s3.bucketConfig) was
// denied, the public bucket is unknown, never a false pass or fail.
func TestExposureHonestUnknown(t *testing.T) {
	all, _ := LoadBuiltinAll(packs.FS, nil)
	rs, _ := rules.Evaluate(nrm(awsScan(collect.Denied)), all)
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::pub"); s != model.OutcomeUnknown {
		t.Errorf("public bucket with denied bucketConfig = %s, want unknown", s)
	}
}

// TestExposureGCP proves the GCP exposure rules fire on a GCP scan.
func TestExposureGCP(t *testing.T) {
	scan := &collect.Scan{
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
	all, _ := LoadBuiltinAll(packs.FS, nil)
	rs, _ := rules.Evaluate(nrm(scan), all)
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-GCP", "//storage.googleapis.com/projects/_/buckets/pub"); s != model.Fail {
		t.Errorf("public GCS bucket = %s, want fail", s)
	}
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-GCP", "//storage.googleapis.com/projects/_/buckets/priv"); s != model.Pass {
		t.Errorf("private GCS bucket = %s, want pass", s)
	}
	if s := stateFor(rs, "CORE-P0-DATABASE-PUBLIC-GCP", "//cloudsql.googleapis.com/projects/p/instances/open"); s != model.Fail {
		t.Errorf("open Cloud SQL = %s, want fail", s)
	}
	if s := stateFor(rs, "CORE-P0-DATABASE-PUBLIC-GCP", "//cloudsql.googleapis.com/projects/p/instances/scoped"); s != model.Pass {
		t.Errorf("scoped-network Cloud SQL = %s, want pass (public IP but not open to 0.0.0.0/0)", s)
	}
}

func ctrl(id string, attrs map[string]string) collect.Node {
	return collect.Node{Type: model.NodeControl, NativeID: id, Attributes: attrs}
}

// TestKeyManagement proves the key-management rules fire per cloud: AWS/GCP key rotation
// disabled and Azure Key Vault purge protection disabled, with the enabled cases passing.
func TestKeyManagement(t *testing.T) {
	all, _ := LoadBuiltinAll(packs.FS, nil)

	aws := &collect.Scan{
		Nodes: []collect.Node{
			ctrl("arn:aws:kms:us-east-1:1:key/norot", map[string]string{"rotation_enabled": "false"}),
			ctrl("arn:aws:kms:us-east-1:1:key/rot", map[string]string{"rotation_enabled": "true"}),
		},
		Completeness: []collect.Completeness{{Service: "kms.keyDetails", Status: collect.Complete}},
	}
	ra, _ := rules.Evaluate(nrm(aws), all)
	if s := stateFor(ra, "CORE-P0-KMS-ROTATION-AWS", "arn:aws:kms:us-east-1:1:key/norot"); s != model.Fail {
		t.Errorf("AWS key without rotation = %s, want fail", s)
	}
	if s := stateFor(ra, "CORE-P0-KMS-ROTATION-AWS", "arn:aws:kms:us-east-1:1:key/rot"); s != model.Pass {
		t.Errorf("AWS rotating key = %s, want pass", s)
	}

	gcp := &collect.Scan{
		Nodes:        []collect.Node{ctrl("//cloudkms.googleapis.com/projects/p/.../k", map[string]string{"rotation_configured": "false"})},
		Completeness: []collect.Completeness{{Service: "cloudkms.cryptoKeys", Status: collect.Complete}},
	}
	rg, _ := rules.Evaluate(nrm(gcp), all)
	if s := stateFor(rg, "CORE-P0-KMS-ROTATION-GCP", "//cloudkms.googleapis.com/projects/p/.../k"); s != model.Fail {
		t.Errorf("GCP key without rotation = %s, want fail", s)
	}

	az := &collect.Scan{
		Nodes: []collect.Node{
			ctrl("/subscriptions/s/.../vaults/nopurge", map[string]string{"azure_type": "key_vault"}), // purge_protection absent
			ctrl("/subscriptions/s/.../vaults/purge", map[string]string{"azure_type": "key_vault", "purge_protection": "true"}),
		},
		Completeness: []collect.Completeness{{Service: "keyvault.vaults", Status: collect.Complete}},
	}
	rz, _ := rules.Evaluate(nrm(az), all)
	if s := stateFor(rz, "CORE-P0-KEYVAULT-PURGE-AZURE", "/subscriptions/s/.../vaults/nopurge"); s != model.Fail {
		t.Errorf("Azure vault without purge protection = %s, want fail", s)
	}
	if s := stateFor(rz, "CORE-P0-KEYVAULT-PURGE-AZURE", "/subscriptions/s/.../vaults/purge"); s != model.Pass {
		t.Errorf("Azure vault with purge protection = %s, want pass", s)
	}
}

// TestExposureAzure proves the Azure exposure rules fire on an Azure scan.
func TestExposureAzure(t *testing.T) {
	scan := &collect.Scan{
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
	all, _ := LoadBuiltinAll(packs.FS, nil)
	rs, _ := rules.Evaluate(nrm(scan), all)
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AZURE", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/pub"); s != model.Fail {
		t.Errorf("public storage account = %s, want fail", s)
	}
	if s := stateFor(rs, "CORE-P0-STORAGE-PUBLIC-AZURE", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/priv"); s != model.Pass {
		t.Errorf("private storage account = %s, want pass", s)
	}
	if s := stateFor(rs, "CORE-P0-DATABASE-PUBLIC-AZURE", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/pub"); s != model.Fail {
		t.Errorf("public SQL server = %s, want fail", s)
	}
}
