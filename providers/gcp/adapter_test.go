package gcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/logging"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

func staticToken(tok string) oauth2.TokenSource {
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok})
}

// adapterWith builds an Adapter with a fixed project and token, and a stub
// introspection, so Resolve is fully hermetic.
func adapterWith(projectID, token string, introspect func(context.Context, oauth2.TokenSource) (string, error)) *Adapter {
	return &Adapter{
		loadADC: func(context.Context, ...string) (credentials, error) {
			return credentials{projectID: projectID, tokens: staticToken(token)}, nil
		},
		introspect: introspect,
	}
}

func returns(email string, err error) func(context.Context, oauth2.TokenSource) (string, error) {
	return func(context.Context, oauth2.TokenSource) (string, error) { return email, err }
}

func TestAdapterResolvesIdentity(t *testing.T) {
	a := adapterWith("scanner-project", "ya29.tok", returns("scanner@scanner-project.iam.gserviceaccount.com", nil))
	id, err := a.Resolve(context.Background(), model.GCP, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Provider != model.GCP || id.Account != "scanner-project" ||
		id.Principal != "scanner@scanner-project.iam.gserviceaccount.com" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestAdapterEmptyProjectResolvesWithEmptyAccount(t *testing.T) {
	// A user credential with no default project: account is empty, principal
	// still identified. This is not an error.
	a := adapterWith("", "ya29.tok", returns("user@example.com", nil))
	id, err := a.Resolve(context.Background(), model.GCP, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.Account != "" || id.Principal != "user@example.com" {
		t.Fatalf("identity = %+v, want empty account and a principal", id)
	}
}

func TestAdapterNoEmailFailsClosed(t *testing.T) {
	id, err := adapterWith("proj", "ya29.tok", returns("", nil)).Resolve(context.Background(), model.GCP, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("empty email did not fail closed: id=%+v err=%v", id, err)
	}
}

func TestAdapterClassifiesFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want auth.Kind
	}{
		{"401 unauthorized", &tokeninfoError{status: http.StatusUnauthorized}, auth.KindExpired},
		{"403 forbidden", &tokeninfoError{status: http.StatusForbidden}, auth.KindDenied},
		{"500 server error", &tokeninfoError{status: http.StatusInternalServerError}, auth.KindUnknown},
		{"plain error", errors.New("could not find default credentials"), auth.KindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := adapterWith("proj", "ya29.tok", returns("", tc.err)).Resolve(context.Background(), model.GCP, auth.Discovery)
			if err == nil || !id.IsZero() {
				t.Fatalf("want failure with zero identity, got id=%+v err=%v", id, err)
			}
			var ae *auth.Error
			if !errors.As(err, &ae) {
				t.Fatalf("error is not *auth.Error: %T", err)
			}
			if ae.Kind != tc.want {
				t.Fatalf("kind = %v, want %v", ae.Kind, tc.want)
			}
		})
	}
}

func TestAdapterADCFailureFailsClosed(t *testing.T) {
	a := &Adapter{
		loadADC: func(context.Context, ...string) (credentials, error) {
			return credentials{}, errors.New("could not find default credentials")
		},
		introspect: returns("x@y", nil),
	}
	id, err := a.Resolve(context.Background(), model.GCP, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("ADC failure did not fail closed: id=%+v err=%v", id, err)
	}
}

func TestAdapterRejectsNonGCPProvider(t *testing.T) {
	id, err := adapterWith("proj", "ya29.tok", returns("e@x", nil)).Resolve(context.Background(), model.AWS, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("adapter resolved a non-gcp provider: id=%+v err=%v", id, err)
	}
}

// TestAdapterNeverLeaksAccessToken is the token no-leak proof this adapter needs
// specifically: it is the first adapter to transmit a real access token to an
// external endpoint, so a leak of the token itself, not only of an error
// message, must be impossible. A stub introspection reads the real access token
// from the source and embeds it verbatim in its error (the worst case: the SDK
// leaked the token into a URL or message). The token must then escape through no
// surface: the error string, its fmt verbs, or a record logged through the real
// redacting handler.
func TestAdapterNeverLeaksAccessToken(t *testing.T) {
	token := "ya29." + strings.Repeat("S", 60) // a sentinel access token

	leaky := func(_ context.Context, ts oauth2.TokenSource) (string, error) {
		tok, _ := ts.Token()
		return "", fmt.Errorf("GET https://oauth2.googleapis.com/tokeninfo?access_token=%s returned 500", tok.AccessToken)
	}
	_, err := adapterWith("proj", token, leaky).Resolve(context.Background(), model.GCP, auth.Discovery)
	if err == nil {
		t.Fatal("expected a failure")
	}

	surfaces := []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), logged(t, err)}
	for i, s := range surfaces {
		if strings.Contains(s, token) {
			t.Fatalf("surface %d leaked the access token: %q", i, s)
		}
		if !strings.Contains(s, redact.Placeholder) {
			t.Fatalf("surface %d has no redaction placeholder: %q", i, s)
		}
	}
}

// TestResolvedIdentityHoldsNoToken proves the success path cannot carry the
// token out either: a resolved Identity contains only the account and principal,
// never the access token.
func TestResolvedIdentityHoldsNoToken(t *testing.T) {
	token := "ya29." + strings.Repeat("T", 60)
	id, err := adapterWith("proj", token, returns("e@example.com", nil)).Resolve(context.Background(), model.GCP, auth.Discovery)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(id.Account, token) || strings.Contains(id.Principal, token) || strings.Contains(fmt.Sprintf("%+v", id), token) {
		t.Fatalf("resolved identity carried the access token: %+v", id)
	}
}

// TestResolveCredentialLoadsOnceWithBothScopes proves the scan seam: the
// credential is resolved once, carrying both the identity and collection scopes,
// and returns both the identity and a token source for the collectors.
func TestResolveCredentialLoadsOnceWithBothScopes(t *testing.T) {
	var rec [][]string
	id, ts, err := recordingAdapter("scanner-project", "ya29.tok", &rec).
		resolveCredential(context.Background(), model.GCP, auth.Discovery)
	if err != nil {
		t.Fatalf("resolveCredential: %v", err)
	}
	if len(rec) != 1 {
		t.Fatalf("ADC loaded %d times, want 1", len(rec))
	}
	if !hasScope(rec[0], identityScope) || !hasScope(rec[0], collectionScope) {
		t.Fatalf("the load did not carry both scopes: %v", rec[0])
	}
	if id.Account != "scanner-project" {
		t.Errorf("account = %q, want scanner-project", id.Account)
	}
	if ts == nil {
		t.Error("resolveCredential returned no token source")
	}
}

// TestResolveRequestsOnlyIdentityScope proves auth plan stays least-privilege:
// the zero-permission identity probe never requests the broad collection scope.
func TestResolveRequestsOnlyIdentityScope(t *testing.T) {
	var rec [][]string
	if _, err := recordingAdapter("proj", "ya29.tok", &rec).
		Resolve(context.Background(), model.GCP, auth.Discovery); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rec) != 1 || len(rec[0]) != 1 || rec[0][0] != identityScope {
		t.Fatalf("Resolve requested scopes %v; want only the identity scope", rec)
	}
	if hasScope(rec[0], collectionScope) {
		t.Fatal("auth plan requested the broad collection scope; it must stay narrow")
	}
}

// TestAdapterViaRegistry proves the adapter plugs into the production registry.
func TestAdapterViaRegistry(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(model.GCP, adapterWith("p1", "ya29.tok", returns("sa@p1.iam.gserviceaccount.com", nil)))
	id, err := reg.Resolve(context.Background(), model.GCP, auth.Discovery)
	if err != nil || id.Principal != "sa@p1.iam.gserviceaccount.com" {
		t.Fatalf("registry resolve: id=%+v err=%v", id, err)
	}
}

// logged renders err through the real redacting JSON handler.
func logged(t *testing.T, err error) string {
	t.Helper()
	var buf bytes.Buffer
	log := logging.New(&buf, slog.LevelError, logging.FormatJSON)
	log.Error(err.Error(), "err", err)
	return buf.String()
}
