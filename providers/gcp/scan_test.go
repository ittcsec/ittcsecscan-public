package gcp

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// recordingAdapter builds an Adapter whose ADC load records the scopes of each
// call, so a test can assert how many times, and with which scopes, the
// credential is resolved. The tenant lister and introspection are stubbed, so
// resolution is hermetic.
func recordingAdapter(projectID, token string, rec *[][]string) *Adapter {
	return &Adapter{
		loadADC: func(_ context.Context, scopes ...string) (credentials, error) {
			*rec = append(*rec, append([]string(nil), scopes...))
			return credentials{projectID: projectID, tokens: staticToken(token)}, nil
		},
		introspect: returns("scanner@p.iam.gserviceaccount.com", nil),
	}
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// TestSourceCollectorsResolveCredentialOnceNotOncePerScope is the regression
// guard for the single-resolution guarantee, stated for the GCP case explicitly
// so a future reader does not mistake the two token scopes for the guarantee
// having weakened.
//
// GCP binds OAuth scopes at credential creation, so serving both the identity
// call and the collection from one credential means loading ADC ONCE with BOTH
// the identity scope and the collection scope. That is one resolution, not one
// scope: the guarantee is that the credential is resolved once, so the reported
// identity and the collection cannot come from two different resolutions (which
// across a token rotation could otherwise report one principal while collecting
// as another). This asserts ADC is loaded exactly once, and that the single load
// carries both scopes.
func TestSourceCollectorsResolveCredentialOnceNotOncePerScope(t *testing.T) {
	var rec [][]string
	s := &Source{adapter: recordingAdapter("scanner-project", "ya29.tok", &rec)}

	account, collectors, err := s.Collectors(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collectors: %v", err)
	}
	if len(rec) != 1 {
		t.Fatalf("ADC loaded %d times; one resolution must serve both the identity call and the collection", len(rec))
	}
	if !hasScope(rec[0], identityScope) || !hasScope(rec[0], collectionScope) {
		t.Fatalf("the single load did not carry both scopes: %v", rec[0])
	}
	if account != "scanner-project" {
		t.Errorf("account = %q, want scanner-project", account)
	}
	if len(collectors) == 0 {
		t.Error("no collectors built")
	}
	if s.Provider() != model.GCP {
		t.Errorf("provider = %q, want gcp", s.Provider())
	}
}

// TestSourceCollectorsPropagatesAuthFailure proves an authentication failure is
// surfaced as an error, never as an empty (and therefore silently clean) set of
// collectors.
func TestSourceCollectorsPropagatesAuthFailure(t *testing.T) {
	s := &Source{adapter: adapterWith("proj", "ya29.tok", returns("", &tokeninfoError{status: 403}))}
	if _, _, err := s.Collectors(context.Background(), nil); err == nil {
		t.Fatal("Collectors: want an error on auth failure, got nil")
	}
}
