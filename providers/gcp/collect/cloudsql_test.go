package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// twoSQLInstances is an instances.list page: one public-IP MySQL instance with a CMK,
// a service agent, and an authorized network, and one private-IP Postgres instance.
const twoSQLInstances = `{"items":[
	{"name":"db-public","region":"us-central1","databaseVersion":"MYSQL_8_0","state":"RUNNABLE",
	 "connectionName":"proj:us-central1:db-public",
	 "serviceAccountEmailAddress":"p-111@gcp-sa-cloud-sql.iam.gserviceaccount.com",
	 "diskEncryptionConfiguration":{"kmsKeyName":"projects/proj/locations/us-central1/keyRings/r/cryptoKeys/k"},
	 "settings":{"dataDiskType":"PD_SSD","storageAutoResize":true,"deletionProtectionEnabled":true,
	   "ipConfiguration":{"ipv4Enabled":true,"sslMode":"ENCRYPTED_ONLY","requireSsl":true,
	     "authorizedNetworks":[{"value":"203.0.113.0/24","name":"office"}]},
	   "backupConfiguration":{"enabled":true,"pointInTimeRecoveryEnabled":true}}},
	{"name":"db-private","region":"us-east1","databaseVersion":"POSTGRES_16","state":"RUNNABLE",
	 "settings":{"ipConfiguration":{"ipv4Enabled":false,"privateNetwork":"projects/proj/global/networks/vpc1"},
	   "backupConfiguration":{"enabled":false}}}
]}`

func sqlStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{"/instances": twoSQLInstances}}
}

func runCloudSQL(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newCloudSQLCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func sqlNode(s collect.Scan, project, name string) (collect.Node, bool) {
	id := sqlInstanceResourceName(project, name)
	for _, n := range s.Nodes {
		if n.Type == model.NodeDataStore && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestCloudSQLMapsInstances proves instances become data-store nodes keyed by full
// resource name, with the CMK and private network as forward-key facts and the public
// IP, SSL mode, and authorized networks recorded as raw facts (no verdict).
func TestCloudSQLMapsInstances(t *testing.T) {
	s := runCloudSQL(t, "proj", sqlStub())

	pub, ok := sqlNode(s, "proj", "db-public")
	if !ok {
		t.Fatal("db-public not keyed by its full resource name")
	}
	for k, want := range map[string]string{
		"region": "us-central1", "database_version": "MYSQL_8_0", "state": "RUNNABLE",
		"public_ip_enabled": "true", "ssl_mode": "ENCRYPTED_ONLY", "require_ssl": "true",
		"authorized_networks": "203.0.113.0/24", "customer_managed_encryption": "true",
		"cmk_key":        "projects/proj/locations/us-central1/keyRings/r/cryptoKeys/k",
		"backup_enabled": "true", "point_in_time_recovery": "true", "deletion_protection": "true",
		"service_account": "p-111@gcp-sa-cloud-sql.iam.gserviceaccount.com",
	} {
		if pub.Attributes[k] != want {
			t.Errorf("db-public %s = %q, want %q", k, pub.Attributes[k], want)
		}
	}

	priv, ok := sqlNode(s, "proj", "db-private")
	if !ok {
		t.Fatal("db-private not emitted")
	}
	for k, want := range map[string]string{
		"public_ip_enabled": "false", "private_network": "projects/proj/global/networks/vpc1",
		"customer_managed_encryption": "false", "backup_enabled": "false",
	} {
		if priv.Attributes[k] != want {
			t.Errorf("db-private %s = %q, want %q", k, priv.Attributes[k], want)
		}
	}
	for _, forbidden := range []string{"is_public", "exposed", "compliant"} {
		if _, bad := pub.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "cloudsql.instances"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("cloudsql.instances = %+v, want complete/2", c)
	}
}

// TestCloudSQLRunAsEdge proves the instance-to-service-agent run-as edge, keyed by the
// service account email so it dedups with the identity nodes, and that an instance
// with no service agent produces no edge.
func TestCloudSQLRunAsEdge(t *testing.T) {
	s := runCloudSQL(t, "proj", sqlStub())

	got := false
	for _, l := range s.Links {
		if l.Kind != model.EdgeAssumes {
			continue
		}
		if l.SourceNativeID == sqlInstanceResourceName("proj", "db-public") &&
			l.TargetNativeID == "p-111@gcp-sa-cloud-sql.iam.gserviceaccount.com" {
			got = true
		}
		if l.SourceNativeID == sqlInstanceResourceName("proj", "db-private") {
			t.Errorf("db-private has no service agent, must have no run-as edge; got -> %s", l.TargetNativeID)
		}
	}
	if !got {
		t.Error("missing run-as edge db-public -> its service agent")
	}
	if _, ok := workloadNamed(s, "p-111@gcp-sa-cloud-sql.iam.gserviceaccount.com"); !ok {
		t.Error("service agent not emitted as a workload node keyed by email")
	}
}

func workloadNamed(s collect.Scan, id string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeWorkload && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestCloudSQLNoProjectIsUnsupported proves an empty project id is an Unsupported gap.
func TestCloudSQLNoProjectIsUnsupported(t *testing.T) {
	s := runCloudSQL(t, "", sqlStub())
	if c := completenessOf(s, "cloudsql.instances"); c.Status != collect.Unsupported {
		t.Errorf("cloudsql.instances = %+v, want unsupported", c)
	}
}

// TestCloudSQLDeniedIsGap proves a denied read is a Denied gap that does not fail the
// run and emits no node.
func TestCloudSQLDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "/instances", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newCloudSQLCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "cloudsql.instances") != collect.Denied {
		t.Errorf("cloudsql.instances = %s, want denied", statusOf(s, "cloudsql.instances"))
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 0 {
		t.Errorf("data-store nodes = %d, want 0", n)
	}
}

// TestCloudSQLServiceDisabledIsUnsupported proves a disabled Cloud SQL Admin API is an
// Unsupported gap, not a denial and not a pass.
func TestCloudSQLServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "/instances", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud SQL Admin API is not enabled"}}
	var s collect.Scan
	if err := newCloudSQLCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "cloudsql.instances") != collect.Unsupported {
		t.Errorf("cloudsql.instances = %s, want unsupported", statusOf(s, "cloudsql.instances"))
	}
}

// TestCloudSQLEmptyIsComplete proves an empty project is an honest Complete/0.
func TestCloudSQLEmptyIsComplete(t *testing.T) {
	s := runCloudSQL(t, "proj", &stubGCP{bodies: map[string]string{"/instances": `{}`}})
	if c := completenessOf(s, "cloudsql.instances"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("cloudsql.instances = %+v, want complete/0", c)
	}
}

// TestCloudSQLPaginates proves nextPageToken is followed.
func TestCloudSQLPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"/instances": `{"items":[{"name":"a","region":"us"}],"nextPageToken":"np2"}`,
		"np2":        `{"items":[{"name":"b","region":"us"}]}`,
	}}
	s := runCloudSQL(t, "proj", api)
	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Errorf("instances across pages = %d, want 2", n)
	}
}

// TestCloudSQLEvidenceRedactsToken proves the evidence body is scrubbed.
func TestCloudSQLEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("z", 60)
	api := &stubGCP{bodies: map[string]string{"/instances": `{"items":[{"name":"` + token + `","region":"us"}]}`}}
	s := runCloudSQL(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
