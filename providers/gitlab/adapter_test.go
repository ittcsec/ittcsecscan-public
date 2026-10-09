package gitlab

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
		loadToken:  func() (string, error) { return "tok", nil },
		introspect: func(context.Context, string) (string, error) { return "tanuki", nil },
	}
	id, err := a.Resolve(context.Background(), model.GitLab, auth.Discovery)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Provider != model.GitLab || id.Account != "tanuki" || id.Principal != "tanuki" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func TestResolveMissingTokenFailsClosed(t *testing.T) {
	a := &Adapter{
		loadToken:  func() (string, error) { return "", errors.New("no GITLAB_TOKEN in the environment") },
		introspect: func(context.Context, string) (string, error) { return "tanuki", nil },
	}
	if _, err := a.Resolve(context.Background(), model.GitLab, auth.Discovery); err == nil {
		t.Fatal("expected an error when no token is present")
	}
}

func noEnv(string) (string, bool) { return "", false }

func TestResolveRejectsWrongProvider(t *testing.T) {
	a := New(noEnv)
	if _, err := a.Resolve(context.Background(), model.AWS, auth.Discovery); err == nil {
		t.Fatal("gitlab adapter must reject a non-gitlab provider")
	}
}

func TestNewReadsTokenFromEnv(t *testing.T) {
	a := New(func(k string) (string, bool) {
		if k == "GITLAB_TOKEN" {
			return " tok ", true
		}
		return "", false
	})
	a.introspect = func(context.Context, string) (string, error) { return "tanuki", nil }
	if _, err := a.Resolve(context.Background(), model.GitLab, auth.Discovery); err != nil {
		t.Fatalf("Resolve with an env token: %v", err)
	}
	// Missing env → fail closed.
	b := New(noEnv)
	if _, err := b.Resolve(context.Background(), model.GitLab, auth.Discovery); err == nil {
		t.Fatal("missing GITLAB_TOKEN must fail closed")
	}
}

func TestClassifyStatuses(t *testing.T) {
	cases := map[int]auth.Kind{401: auth.KindExpired, 403: auth.KindDenied, 500: auth.KindUnknown}
	for status, want := range cases {
		if got := classify(&apiStatusError{status: status}); got != want {
			t.Errorf("classify(%d) = %v, want %v", status, got, want)
		}
	}
	if got := classify(errors.New("network")); got != auth.KindUnknown {
		t.Errorf("classify(non-status) = %v, want KindUnknown", got)
	}
}

// A real GitLab token accidentally caught in an error is scrubbed by auth.Fail (redact
// recognizes the glpat- token shape). The token is assembled at runtime so no
// token-shaped literal is committed (which a secret scanner would flag).
func TestResolveErrorScrubsToken(t *testing.T) {
	tok := "glpat-" + strings.Repeat("A0", 10) // matches redact's gitlab-token shape, not a literal
	a := &Adapter{
		loadToken:  func() (string, error) { return tok, nil },
		introspect: func(context.Context, string) (string, error) { return "", errors.New("failed with " + tok) },
	}
	_, err := a.Resolve(context.Background(), model.GitLab, auth.Discovery)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); contains(got, tok) {
		t.Errorf("error leaked the token: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
