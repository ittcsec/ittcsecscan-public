package okta

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestResolveReturnsIdentity(t *testing.T) {
	a := &Adapter{
		loadCreds:  func() (string, string, error) { return "https://acme.okta.com", "tok", nil },
		introspect: func(context.Context, string, string) error { return nil },
	}
	id, err := a.Resolve(context.Background(), model.Okta, auth.Discovery)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Provider != model.Okta || id.Account != "https://acme.okta.com" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func noEnv(string) (string, bool) { return "", false }

func TestCredsFromRequiresBoth(t *testing.T) {
	// Missing everything.
	if _, _, err := credsFrom(noEnv); err == nil {
		t.Error("missing OKTA_ORG_URL must fail closed")
	}
	// Org but no token.
	orgOnly := func(k string) (string, bool) {
		if k == "OKTA_ORG_URL" {
			return "https://acme.okta.com/", true
		}
		return "", false
	}
	if _, _, err := credsFrom(orgOnly); err == nil {
		t.Error("missing OKTA_API_TOKEN must fail closed")
	}
	// Both present: org trailing slash trimmed.
	both := func(k string) (string, bool) {
		switch k {
		case "OKTA_ORG_URL":
			return "https://acme.okta.com/", true
		case "OKTA_API_TOKEN":
			return " tok ", true
		}
		return "", false
	}
	org, tok, err := credsFrom(both)
	if err != nil || org != "https://acme.okta.com" || tok != "tok" {
		t.Errorf("credsFrom = (%q, %q, %v)", org, tok, err)
	}
}

func TestResolveRejectsWrongProvider(t *testing.T) {
	a := New(noEnv)
	if _, err := a.Resolve(context.Background(), model.AWS, auth.Discovery); err == nil {
		t.Fatal("okta adapter must reject a non-okta provider")
	}
}

func TestClassifyStatuses(t *testing.T) {
	cases := map[int]auth.Kind{401: auth.KindExpired, 403: auth.KindDenied, 500: auth.KindUnknown}
	for status, want := range cases {
		if got := classify(&apiStatusError{status: status}); got != want {
			t.Errorf("classify(%d) = %v, want %v", status, got, want)
		}
	}
}

// An Okta API token accidentally caught in an error carried in an SSWS header is scrubbed
// by auth.Fail (redact recognizes the SSWS scheme). The token is assembled at runtime.
func TestResolveErrorScrubsToken(t *testing.T) {
	tok := "00" + strings.Repeat("Ab3", 14)
	a := &Adapter{
		loadCreds:  func() (string, string, error) { return "https://acme.okta.com", tok, nil },
		introspect: func(context.Context, string, string) error { return errors.New("failed: Authorization: SSWS " + tok) },
	}
	_, err := a.Resolve(context.Background(), model.Okta, auth.Discovery)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), tok) {
		t.Errorf("error leaked the token: %q", err.Error())
	}
}
