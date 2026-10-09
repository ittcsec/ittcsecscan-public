package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// twoSinks is a sinks.list page: one active sink routing to a bucket, one disabled
// sink routing to a topic.
const twoSinks = `{"sinks":[
	{"name":"all-audit","destination":"logging.googleapis.com/projects/proj/locations/global/buckets/_Default",
	 "filter":"logName:cloudaudit.googleapis.com","writerIdentity":"serviceAccount:p-1@gcp-sa-logging.iam.gserviceaccount.com"},
	{"name":"to-topic","destination":"pubsub.googleapis.com/projects/proj/topics/logs","disabled":true}
]}`

// twoBucketsLog is a buckets.list page: the _Required bucket (locked, 400d) and a CMK
// analytics bucket.
const twoBucketsLog = `{"buckets":[
	{"name":"projects/proj/locations/global/buckets/_Required","retentionDays":400,"locked":true,"lifecycleState":"ACTIVE"},
	{"name":"projects/proj/locations/us/buckets/secure","retentionDays":30,"analyticsEnabled":true,
	 "cmekSettings":{"kmsKeyName":"projects/proj/locations/us/keyRings/r/cryptoKeys/k"}}
]}`

func loggingStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"/sinks":   twoSinks,
		"/buckets": twoBucketsLog,
	}}
}

func runLogging(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newLoggingCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func controlNamed(s collect.Scan, id string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestLoggingMapsSinks proves sinks become control nodes keyed by full resource name
// with the destination recorded as a forward-key fact and disabled state as a raw fact.
func TestLoggingMapsSinks(t *testing.T) {
	s := runLogging(t, "proj", loggingStub())

	audit, ok := controlNamed(s, "//logging.googleapis.com/projects/proj/sinks/all-audit")
	if !ok {
		t.Fatal("all-audit sink not keyed by its full resource name")
	}
	for k, want := range map[string]string{
		"destination":     "logging.googleapis.com/projects/proj/locations/global/buckets/_Default",
		"filter":          "logName:cloudaudit.googleapis.com",
		"writer_identity": "serviceAccount:p-1@gcp-sa-logging.iam.gserviceaccount.com",
	} {
		if audit.Attributes[k] != want {
			t.Errorf("all-audit %s = %q, want %q", k, audit.Attributes[k], want)
		}
	}
	// disabled is recorded explicitly even when false, so an active sink is an
	// explicit fact, never a silent gap (the pattern used across the collectors).
	if audit.Attributes["disabled"] != "false" {
		t.Errorf("all-audit disabled = %q, want explicit false", audit.Attributes["disabled"])
	}
	if topic, _ := controlNamed(s, "//logging.googleapis.com/projects/proj/sinks/to-topic"); topic.Attributes["disabled"] != "true" {
		t.Errorf("to-topic disabled = %q, want true", topic.Attributes["disabled"])
	}
	if c := completenessOf(s, "logging.sinks"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("logging.sinks = %+v, want complete/2", c)
	}
}

// TestLoggingMapsBuckets proves buckets become control nodes with retention, lock, and
// the CMK as a forward-key fact, no verdict synthesized.
func TestLoggingMapsBuckets(t *testing.T) {
	s := runLogging(t, "proj", loggingStub())

	req, ok := controlNamed(s, "//logging.googleapis.com/projects/proj/locations/global/buckets/_Required")
	if !ok {
		t.Fatal("_Required bucket not emitted")
	}
	for k, want := range map[string]string{
		"retention_days": "400", "locked": "true", "lifecycle_state": "ACTIVE",
	} {
		if req.Attributes[k] != want {
			t.Errorf("_Required %s = %q, want %q", k, req.Attributes[k], want)
		}
	}
	secure, _ := controlNamed(s, "//logging.googleapis.com/projects/proj/locations/us/buckets/secure")
	if secure.Attributes["cmek_key"] != "projects/proj/locations/us/keyRings/r/cryptoKeys/k" {
		t.Errorf("secure cmek_key = %q, want the KMS key path", secure.Attributes["cmek_key"])
	}
	if secure.Attributes["analytics_enabled"] != "true" {
		t.Errorf("secure analytics_enabled = %q, want true", secure.Attributes["analytics_enabled"])
	}
	for _, forbidden := range []string{"compliant", "sufficient", "retention_ok"} {
		if _, bad := req.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "logging.buckets"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("logging.buckets = %+v, want complete/2", c)
	}
}

// TestLoggingSinksDeniedIsGap proves a denied sinks read is a Denied gap that does not
// fail the run and does not block the bucket read.
func TestLoggingSinksDeniedIsGap(t *testing.T) {
	api := loggingStub()
	api.failSub = "/sinks"
	api.failWith = &gcpError{status: 403, body: "PERMISSION_DENIED"}
	var s collect.Scan
	if err := newLoggingCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "logging.sinks") != collect.Denied {
		t.Errorf("logging.sinks = %s, want denied", statusOf(s, "logging.sinks"))
	}
	if statusOf(s, "logging.buckets") != collect.Complete {
		t.Errorf("logging.buckets should still be complete, got %s", statusOf(s, "logging.buckets"))
	}
}

// TestLoggingServiceDisabledIsUnsupported proves a disabled Logging API is Unsupported.
func TestLoggingServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "/sinks", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud Logging API is not enabled"}}
	var s collect.Scan
	if err := newLoggingCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "logging.sinks") != collect.Unsupported {
		t.Errorf("logging.sinks = %s, want unsupported", statusOf(s, "logging.sinks"))
	}
}

// TestLoggingEmptyIsComplete proves an empty project is an honest Complete/0.
func TestLoggingEmptyIsComplete(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{"/sinks": `{}`, "/buckets": `{}`}}
	s := runLogging(t, "proj", api)
	for _, svc := range []string{"logging.sinks", "logging.buckets"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestLoggingNoProjectIsUnsupported proves an empty project id is an Unsupported gap.
func TestLoggingNoProjectIsUnsupported(t *testing.T) {
	s := runLogging(t, "", loggingStub())
	for _, svc := range []string{"logging.sinks", "logging.buckets"} {
		if c := completenessOf(s, svc); c.Status != collect.Unsupported {
			t.Errorf("%s = %+v, want unsupported", svc, c)
		}
	}
}

// TestLoggingPaginates proves nextPageToken is followed for sinks.
func TestLoggingPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"/sinks":   `{"sinks":[{"name":"a"}],"nextPageToken":"np2"}`,
		"np2":      `{"sinks":[{"name":"b"}]}`,
		"/buckets": `{}`,
	}}
	s := runLogging(t, "proj", api)
	sinks := 0
	for _, n := range s.Nodes {
		if strings.Contains(n.NativeID, "/sinks/") {
			sinks++
		}
	}
	if sinks != 2 {
		t.Errorf("sinks across pages = %d, want 2", sinks)
	}
}

// TestLoggingEvidenceRedactsToken proves the evidence body is scrubbed.
func TestLoggingEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("z", 60)
	api := &stubGCP{bodies: map[string]string{
		"/sinks":   `{"sinks":[{"name":"` + token + `"}]}`,
		"/buckets": `{}`,
	}}
	s := runLogging(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
