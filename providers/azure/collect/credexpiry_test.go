package collect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// fixedNow is the deterministic clock the credential tests use.
func fixedNow() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) }

// appsOnePage carries a cert credential (expired), a client secret (valid), and
// the secret-adjacent "hint" and never-on-read "secretText" fields Graph can
// return, so the strip-before-evidence behaviour is exercised against real shapes.
const appsOnePage = `{"value":[
	{"id":"app-obj-1","appId":"00000000-0000-0000-0000-000000000001","displayName":"Legacy API",
	 "keyCredentials":[
		{"keyId":"kc-1","displayName":"signing cert","startDateTime":"2024-01-01T00:00:00Z","endDateTime":"2025-01-01T00:00:00Z","usage":"Verify","type":"AsymmetricX509Cert","key":"BASE64CERTPUBLICKEY"}],
	 "passwordCredentials":[
		{"keyId":"pc-1","displayName":"ci secret","startDateTime":"2026-01-01T00:00:00Z","endDateTime":"2027-01-01T00:00:00Z","hint":"abc","secretText":null}]}
]}`

func runAppCred(t *testing.T, api graphAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newAppCredentialCollector("tenant-1", api, fixedNow).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func credNode(s collect.Scan, keyID string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeCredential && n.NativeID == keyID {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestAppCredentialMapsExpiry proves each app credential becomes a credential node
// keyed by its keyId, with the expiry facts computed against the fixed clock: an
// end date in the past is expired, a future one is not, and the owning app carries
// the aggregate signal with a contains_secret edge to each credential.
func TestAppCredentialMapsExpiry(t *testing.T) {
	s := runAppCred(t, &stubGraph{bodies: map[string]string{"/applications?": appsOnePage}})

	if c := completenessOf(s, "entra.appCredentials"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("entra.appCredentials = %+v, want complete/1", c)
	}

	cert, ok := credNode(s, "kc-1")
	if !ok {
		t.Fatal("certificate credential node kc-1 not emitted")
	}
	if cert.Attributes["credential_type"] != "certificate" || cert.Attributes["expired"] != "true" {
		t.Errorf("cert facts = %+v, want certificate/expired", cert.Attributes)
	}
	if cert.Attributes["app_id"] != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("cert app_id = %q", cert.Attributes["app_id"])
	}
	// kc-1 lifetime 2024-01-01..2025-01-01 is 366 days (2024 is a leap year).
	if cert.Attributes["credential_lifetime_days"] != "366" {
		t.Errorf("cert credential_lifetime_days = %q, want 366", cert.Attributes["credential_lifetime_days"])
	}

	secret, ok := credNode(s, "pc-1")
	if !ok {
		t.Fatal("password credential node pc-1 not emitted")
	}
	if secret.Attributes["credential_type"] != "client_secret" || secret.Attributes["expired"] != "false" {
		t.Errorf("secret facts = %+v, want client_secret/not-expired", secret.Attributes)
	}
	// pc-1 lifetime 2026-01-01..2027-01-01 is 365 days.
	if secret.Attributes["credential_lifetime_days"] != "365" {
		t.Errorf("secret credential_lifetime_days = %q, want 365", secret.Attributes["credential_lifetime_days"])
	}

	// The owning app node carries the aggregate dormancy/expiry signal.
	var app collect.Node
	for _, n := range s.Nodes {
		if n.Type == model.NodeWorkload && n.NativeID == "app-obj-1" {
			app = n
		}
	}
	if app.Attributes["azure_type"] != "app_registration" || app.Attributes["has_expired_credential"] != "true" || app.Attributes["credential_count"] != "2" {
		t.Errorf("app node facts = %+v", app.Attributes)
	}
	// The contains_secret edges join the app to both its credentials.
	edges := 0
	for _, l := range s.Links {
		if l.Kind == model.EdgeContainsSecret && l.SourceNativeID == "app-obj-1" {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("contains_secret edges = %d, want 2", edges)
	}
}

// TestAppCredentialHintNeverInEvidence proves the secret-adjacent passwordCredentials
// "hint" and the write-once "secretText", and the certificate public "key", never
// reach evidence: evidence is built from a hint-free typed model, so these fields
// are absent by construction. This is the amendment-1 guarantee.
func TestAppCredentialHintNeverInEvidence(t *testing.T) {
	s := runAppCred(t, &stubGraph{bodies: map[string]string{"/applications?": appsOnePage}})
	if len(s.Envelopes) == 0 {
		t.Fatal("no evidence emitted")
	}
	for _, e := range s.Envelopes {
		body := string(e.Response)
		for _, forbidden := range []string{"hint", "secretText", "BASE64CERTPUBLICKEY", `"abc"`} {
			if strings.Contains(body, forbidden) {
				t.Errorf("evidence contains secret-adjacent field %q: %s", forbidden, body)
			}
		}
	}
	// And it is not merely empty: the non-secret metadata is present.
	joined := ""
	for _, e := range s.Envelopes {
		joined += string(e.Response)
	}
	if !strings.Contains(joined, "kc-1") || !strings.Contains(joined, "Legacy API") {
		t.Errorf("evidence lost the non-secret metadata it should carry: %s", joined)
	}
}

// TestAppCredentialMissingExpiryIsUnknown proves a credential with no end date is
// represented as unknown (no expired fact), never silently treated as not-expired.
func TestAppCredentialMissingExpiryIsUnknown(t *testing.T) {
	const noEnd = `{"value":[{"id":"app-2","appId":"a2","displayName":"NoExpiry",
		"passwordCredentials":[{"keyId":"pc-x","displayName":"s","startDateTime":"2026-01-01T00:00:00Z","endDateTime":""}]}]}`
	s := runAppCred(t, &stubGraph{bodies: map[string]string{"/applications?": noEnd}})
	n, ok := credNode(s, "pc-x")
	if !ok {
		t.Fatal("credential pc-x not emitted")
	}
	if _, has := n.Attributes["expired"]; has {
		t.Errorf("a credential with no end date must not claim an expired verdict: %+v", n.Attributes)
	}
}

// TestAppCredentialDeniedIsGap proves a denied list is an honest Denied gap with no
// nodes, never an empty-complete that would read as "this tenant has no app
// credentials".
func TestAppCredentialDeniedIsGap(t *testing.T) {
	s := runAppCred(t, &stubGraph{failSub: "/applications?", failWith: &azureError{status: 403, body: "Authorization_RequestDenied"}})
	if statusOf(s, "entra.appCredentials") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "entra.appCredentials"))
	}
	if nodesByType(s)[model.NodeCredential] != 0 {
		t.Error("no credential nodes should be emitted on a denied read")
	}
}
