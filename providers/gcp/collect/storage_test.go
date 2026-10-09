package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// twoBuckets is a buckets.list page: one bucket public via an IAM binding with
// uniform access on and CMEK, and one "bare" bucket (no uniform access, no
// versioning, no CMEK) that is public via a legacy ACL grant.
const twoBuckets = `{"items":[
	{"name":"bkt-public","location":"US","locationType":"multi-region","storageClass":"STANDARD",
	 "iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true},"publicAccessPrevention":"enforced"},
	 "versioning":{"enabled":true},
	 "encryption":{"defaultKmsKeyName":"projects/p/locations/us/keyRings/r/cryptoKeys/k"},
	 "labels":{"env":"prod"}},
	{"name":"bkt-bare","location":"us-east1","locationType":"region","storageClass":"STANDARD",
	 "acl":[{"entity":"allUsers","role":"READER"},{"entity":"project-owners-1","role":"OWNER"}]}
]}`

func gcsStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"projection=full": twoBuckets,
		"bkt-public/iam":  `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers"]},{"role":"roles/storage.admin","members":["user:a@b.com"]}]}`,
		"bkt-bare/iam":    `{"bindings":[{"role":"roles/storage.admin","members":["user:a@b.com"]}]}`,
	}}
}

func runStorage(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newStorageCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func bucketNode(s collect.Scan, name string) (collect.Node, bool) {
	arn := "//storage.googleapis.com/projects/_/buckets/" + name
	for _, n := range s.Nodes {
		if n.Type == model.NodeDataStore && n.NativeID == arn {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestStorageMapsBuckets proves buckets become data-store nodes keyed by their full
// resource name, with configuration recorded as facts and public access detected
// from both an IAM binding and a legacy ACL grant.
func TestStorageMapsBuckets(t *testing.T) {
	s := runStorage(t, "proj", gcsStub())

	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Fatalf("data-store nodes = %d, want 2", n)
	}
	pub, ok := bucketNode(s, "bkt-public")
	if !ok {
		t.Fatal("bkt-public not keyed by full resource name")
	}
	for k, v := range map[string]string{
		"location": "US", "storage_class": "STANDARD",
		"uniform_bucket_level_access": "true", "public_access_prevention": "enforced",
		"versioning": "enabled", "customer_managed_encryption": "true",
		"default_kms_key": "projects/p/locations/us/keyRings/r/cryptoKeys/k",
		"label:env":       "prod",
		// public via IAM binding, recorded as a fact.
		"iam_all_users_roles": "roles/storage.objectViewer",
	} {
		if pub.Attributes[k] != v {
			t.Errorf("bkt-public %s = %q, want %q", k, pub.Attributes[k], v)
		}
	}

	bare, ok := bucketNode(s, "bkt-bare")
	if !ok {
		t.Fatal("bkt-bare missing")
	}
	// public via legacy ACL, recorded as a fact; the non-public ACL entry is ignored.
	if bare.Attributes["acl_all_users"] != "READER" {
		t.Errorf("bkt-bare acl_all_users = %q, want READER", bare.Attributes["acl_all_users"])
	}

	if statusOf(s, "storage.buckets") != collect.Complete {
		t.Errorf("storage.buckets = %s, want complete", statusOf(s, "storage.buckets"))
	}
	if c := completenessOf(s, "storage.bucketIam"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("storage.bucketIam = %+v, want complete with 2", c)
	}
}

// TestStorageNotConfiguredIsFact proves an absent protection is recorded as an
// explicit fact (via a missing JSON field), never dropped: the bare bucket reports
// uniform access off, no versioning, no CMEK, and inherited public-access
// prevention.
func TestStorageNotConfiguredIsFact(t *testing.T) {
	s := runStorage(t, "proj", gcsStub())
	bare, _ := bucketNode(s, "bkt-bare")
	for k, v := range map[string]string{
		"uniform_bucket_level_access": "false",
		"versioning":                  "disabled",
		"customer_managed_encryption": "false",
		"public_access_prevention":    "inherited",
	} {
		if bare.Attributes[k] != v {
			t.Errorf("bkt-bare %s = %q, want %q (absent config must be a fact)", k, bare.Attributes[k], v)
		}
	}
	if _, ok := bare.Attributes["default_kms_key"]; ok {
		t.Error("bkt-bare should have no default_kms_key attribute")
	}
}

// TestStorageIamDeniedIsGapNotFatal proves a denied per-bucket getIamPolicy is a
// recorded Partial gap, not a run error, and the bucket node is still emitted with
// its configuration (without IAM facts).
func TestStorageIamDeniedIsGapNotFatal(t *testing.T) {
	api := gcsStub()
	api.failSub = "bkt-public/iam"
	api.failWith = &gcpError{status: 403, body: "PERMISSION_DENIED"}
	var s collect.Scan
	if err := newStorageCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied bucket IAM read must not fail the run: %v", err)
	}
	if _, ok := bucketNode(s, "bkt-public"); !ok {
		t.Error("bucket node must still be emitted when its IAM read is denied")
	}
	if pub, _ := bucketNode(s, "bkt-public"); pub.Attributes["iam_all_users_roles"] != "" {
		t.Error("no IAM facts should be recorded when the IAM read was denied")
	}
	if c := completenessOf(s, "storage.bucketIam"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("storage.bucketIam = %+v, want partial denied", c)
	}
}

// TestStorageBucketsDeniedIsGap proves a denied buckets.list is a recorded Denied
// gap with no nodes, not a run error.
func TestStorageBucketsDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "projection=full", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newStorageCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("denied list must not fail the run: %v", err)
	}
	if statusOf(s, "storage.buckets") != collect.Denied {
		t.Errorf("storage.buckets = %s, want denied", statusOf(s, "storage.buckets"))
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 0 {
		t.Errorf("data-store nodes = %d, want 0", n)
	}
}

// TestStorageServiceDisabledIsUnsupported proves a disabled Storage API is
// recorded Unsupported, not Denied.
func TestStorageServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "projection=full", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud Storage API is not enabled"}}
	var s collect.Scan
	if err := newStorageCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("service-disabled must not fail the run: %v", err)
	}
	if statusOf(s, "storage.buckets") != collect.Unsupported {
		t.Errorf("storage.buckets = %s, want unsupported", statusOf(s, "storage.buckets"))
	}
}

// TestStorageBudgetExhaustion proves the shared budget bounds the per-bucket IAM
// pass: with budget only for the list, the IAM pass is a Partial "budget
// exhausted" gap, yet every bucket is still emitted with its configuration.
func TestStorageBudgetExhaustion(t *testing.T) {
	api := gcsStub()
	c := newStorageCollector("proj", api)
	c.budget = collect.NewBudget(1) // buckets.list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 1 {
		t.Errorf("made %d calls under a 1-call budget; want 1", api.calls)
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Errorf("buckets still emitted with config = %d, want 2", n)
	}
	if got := completenessOf(s, "storage.bucketIam"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("storage.bucketIam = %+v, want partial budget-exhausted", got)
	}
}

// TestStorageEmptyProjectIsUnsupported proves that with no project to scope to, the
// enumeration is a represented Unsupported gap, not an error and not a call.
func TestStorageEmptyProjectIsUnsupported(t *testing.T) {
	api := &stubGCP{}
	if s := runStorage(t, "", api); statusOf(s, "storage.buckets") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "storage.buckets"))
	}
	if api.calls != 0 {
		t.Errorf("made %d calls with no project; want 0", api.calls)
	}
}

// TestStorageNoBucketsIsComplete proves an empty project is an honest Complete/0,
// not a gap.
func TestStorageNoBucketsIsComplete(t *testing.T) {
	s := runStorage(t, "proj", &stubGCP{bodies: map[string]string{"projection=full": `{"items":[]}`}})
	if c := completenessOf(s, "storage.buckets"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("storage.buckets = %+v, want complete with 0", c)
	}
	if c := completenessOf(s, "storage.bucketIam"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("storage.bucketIam = %+v, want complete with 0", c)
	}
}

// TestStoragePaginates proves nextPageToken is followed across bucket pages.
func TestStoragePaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"projection=full": `{"items":[{"name":"b1"}],"nextPageToken":"pg2"}`,
		"pg2":             `{"items":[{"name":"b2"}]}`, // 2nd page: matched by the token value in the URL
		"b1/iam":          `{"bindings":[]}`,
		"b2/iam":          `{"bindings":[]}`,
	}}
	s := runStorage(t, "proj", api)
	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Errorf("buckets across pages = %d, want 2", n)
	}
	if c := completenessOf(s, "storage.buckets"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("storage.buckets = %+v, want complete with 2", c)
	}
}

func TestBucketResourceName(t *testing.T) {
	if got := bucketResourceName("my-bkt"); got != "//storage.googleapis.com/projects/_/buckets/my-bkt" {
		t.Errorf("bucketResourceName = %q", got)
	}
}

// TestStorageEvidenceRedactsToken proves the evidence body is scrubbed.
func TestStorageEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("Z", 40)
	api := &stubGCP{bodies: map[string]string{
		"projection=full": `{"items":[{"name":"` + token + `"}]}`,
		token + "/iam":    `{"bindings":[]}`,
	}}
	s := runStorage(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
