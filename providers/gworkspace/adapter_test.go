package gworkspace

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestResolveReturnsIdentity(t *testing.T) {
	a := &Adapter{
		loadToken:  func() (string, error) { return "tok", nil },
		introspect: func(context.Context, string) error { return nil },
	}
	id, err := a.Resolve(context.Background(), model.GoogleWorkspace, auth.Discovery)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Provider != model.GoogleWorkspace || id.Account != "my_customer" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func noEnv(string) (string, bool) { return "", false }

func TestResolveMissingTokenFailsClosed(t *testing.T) {
	a := New(noEnv)
	if _, err := a.Resolve(context.Background(), model.GoogleWorkspace, auth.Discovery); err == nil {
		t.Fatal("missing GOOGLE_WORKSPACE_TOKEN must fail closed")
	}
}

func TestResolveRejectsWrongProvider(t *testing.T) {
	a := New(func(k string) (string, bool) {
		if k == "GOOGLE_WORKSPACE_TOKEN" {
			return "tok", true
		}
		return "", false
	})
	if _, err := a.Resolve(context.Background(), model.AWS, auth.Discovery); err == nil {
		t.Fatal("google workspace adapter must reject a non-google-workspace provider")
	}
}

func TestClassifyStatuses(t *testing.T) {
	cases := map[int]auth.Kind{401: auth.KindExpired, 403: auth.KindDenied, 500: auth.KindUnknown}
	for status, want := range cases {
		if got := classify(&apiStatusError{status: status}); got != want {
			t.Errorf("classify(%d) = %v, want %v", status, got, want)
		}
	}
	if got := classify(errors.New("net")); got != auth.KindUnknown {
		t.Errorf("classify(non-status) = %v, want KindUnknown", got)
	}
}
