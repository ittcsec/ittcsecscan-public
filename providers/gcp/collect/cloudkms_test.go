package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	oneKMSLocation  = `{"locations":[{"name":"projects/proj/locations/us-central1"}]}`
	twoKMSLocations = `{"locations":[
		{"name":"projects/proj/locations/us-central1"},
		{"name":"projects/proj/locations/us-east1"}]}`
	oneKMSRing = `{"keyRings":[{"name":"projects/proj/locations/us-central1/keyRings/r1"}]}`
	// twoKMSKeys: one rotating symmetric software key, one non-rotating HSM signing
	// key whose protection level and algorithm come from the version template.
	twoKMSKeys = `{"cryptoKeys":[
		{"name":"projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/k-rot","purpose":"ENCRYPT_DECRYPT",
		 "rotationPeriod":"7776000s","nextRotationTime":"2026-12-01T00:00:00Z",
		 "primary":{"state":"ENABLED","protectionLevel":"SOFTWARE","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION"},
		 "labels":{"env":"prod"}},
		{"name":"projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/k-norot","purpose":"ASYMMETRIC_SIGN",
		 "versionTemplate":{"protectionLevel":"HSM","algorithm":"EC_SIGN_P256_SHA256"}}
	]}`
)

func kmsStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"/locations":  oneKMSLocation,
		"/keyRings":   oneKMSRing,
		"/cryptoKeys": twoKMSKeys,
	}}
}

func runKMS(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newCloudKMSCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func kmsKeyNode(s collect.Scan, relName string) (collect.Node, bool) {
	full := "//cloudkms.googleapis.com/" + relName
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == full {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestKMSMapsKeys proves the locations -> key rings -> crypto keys fan-out yields a
// control node per key, keyed by full resource name, carrying the relative name as the
// join key plus rotation and protection facts, with no synthesized verdict.
func TestKMSMapsKeys(t *testing.T) {
	s := runKMS(t, "proj", kmsStub())

	rot, ok := kmsKeyNode(s, "projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/k-rot")
	if !ok {
		t.Fatal("k-rot not keyed by its full resource name")
	}
	for k, want := range map[string]string{
		"resource_name":       "projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/k-rot",
		"purpose":             "ENCRYPT_DECRYPT",
		"rotation_period":     "7776000s",
		"rotation_configured": "true",
		"primary_state":       "ENABLED",
		"protection_level":    "SOFTWARE",
		"algorithm":           "GOOGLE_SYMMETRIC_ENCRYPTION",
		"label:env":           "prod",
	} {
		if rot.Attributes[k] != want {
			t.Errorf("k-rot %s = %q, want %q", k, rot.Attributes[k], want)
		}
	}

	norot, ok := kmsKeyNode(s, "projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/k-norot")
	if !ok {
		t.Fatal("k-norot not emitted")
	}
	for k, want := range map[string]string{
		"purpose": "ASYMMETRIC_SIGN", "rotation_configured": "false",
		"protection_level": "HSM", "algorithm": "EC_SIGN_P256_SHA256",
	} {
		if norot.Attributes[k] != want {
			t.Errorf("k-norot %s = %q, want %q", k, norot.Attributes[k], want)
		}
	}
	for _, forbidden := range []string{"weak", "compliant", "rotation_ok"} {
		if _, bad := rot.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "cloudkms.cryptoKeys"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("cloudkms.cryptoKeys = %+v, want complete/2", c)
	}
}

// TestKMSLocationsDeniedIsGap proves a denied top-level locations read is a Denied gap
// (never a pass) that emits no key node.
func TestKMSLocationsDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "/locations", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newCloudKMSCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "cloudkms.cryptoKeys") != collect.Denied {
		t.Errorf("cloudkms.cryptoKeys = %s, want denied", statusOf(s, "cloudkms.cryptoKeys"))
	}
	if n := nodesByType(s)[model.NodeControl]; n != 0 {
		t.Errorf("control nodes = %d, want 0", n)
	}
}

// TestKMSServiceDisabledIsUnsupported proves a disabled Cloud KMS API is Unsupported.
func TestKMSServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "/locations", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud KMS API is not enabled"}}
	var s collect.Scan
	if err := newCloudKMSCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "cloudkms.cryptoKeys") != collect.Unsupported {
		t.Errorf("cloudkms.cryptoKeys = %s, want unsupported", statusOf(s, "cloudkms.cryptoKeys"))
	}
}

// TestKMSPartialWhenRingUnreadable proves that when one location's key-ring read is
// denied, the other location's keys are still collected and the record is Partial (a
// represented gap), never Complete and never a hard failure.
func TestKMSPartialWhenRingUnreadable(t *testing.T) {
	api := &stubGCP{
		bodies: map[string]string{
			"/locations":  twoKMSLocations,
			"/keyRings":   oneKMSRing,
			"/cryptoKeys": twoKMSKeys,
		},
		failSub:  "us-east1/keyRings",
		failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"},
	}
	s := runKMS(t, "proj", api)
	c := completenessOf(s, "cloudkms.cryptoKeys")
	if c.Status != collect.Partial {
		t.Errorf("cloudkms.cryptoKeys = %s, want partial", c.Status)
	}
	if c.Collected != 2 {
		t.Errorf("collected = %d, want 2 (us-central1's keys still gathered)", c.Collected)
	}
}

// TestKMSEmptyIsComplete proves a location with no key rings is an honest Complete/0.
func TestKMSEmptyIsComplete(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{"/locations": oneKMSLocation, "/keyRings": `{}`}}
	s := runKMS(t, "proj", api)
	if c := completenessOf(s, "cloudkms.cryptoKeys"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("cloudkms.cryptoKeys = %+v, want complete/0", c)
	}
}

// TestKMSNoProjectIsUnsupported proves an empty project id is an Unsupported gap.
func TestKMSNoProjectIsUnsupported(t *testing.T) {
	s := runKMS(t, "", kmsStub())
	if c := completenessOf(s, "cloudkms.cryptoKeys"); c.Status != collect.Unsupported {
		t.Errorf("cloudkms.cryptoKeys = %+v, want unsupported", c)
	}
}

// TestKMSPaginates proves cryptoKeys nextPageToken is followed.
func TestKMSPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"/locations":  oneKMSLocation,
		"/keyRings":   oneKMSRing,
		"/cryptoKeys": `{"cryptoKeys":[{"name":"projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/a"}],"nextPageToken":"np2"}`,
		"np2":         `{"cryptoKeys":[{"name":"projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/b"}]}`,
	}}
	s := runKMS(t, "proj", api)
	if n := nodesByType(s)[model.NodeControl]; n != 2 {
		t.Errorf("keys across pages = %d, want 2", n)
	}
}

// TestKMSEvidenceRedactsToken proves the evidence body is scrubbed.
func TestKMSEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("z", 60)
	api := &stubGCP{bodies: map[string]string{
		"/locations":  oneKMSLocation,
		"/keyRings":   oneKMSRing,
		"/cryptoKeys": `{"cryptoKeys":[{"name":"projects/proj/locations/us-central1/keyRings/r1/cryptoKeys/` + token + `"}]}`,
	}}
	s := runKMS(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
