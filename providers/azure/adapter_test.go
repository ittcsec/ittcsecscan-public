package azure

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// stubLister is an offline tenantLister. It returns tenants/err verbatim, so a
// test drives resolved, denied, expired, and token-bearing failures with no
// network and no real SDK.
type stubLister struct {
	tenants []tenantInfo
	err     error
}

func (s stubLister) list(context.Context) ([]tenantInfo, error) { return s.tenants, s.err }

// adapterWith builds an Adapter whose credential load is a no-op and whose
// lister is the given stub, so Resolve is fully hermetic.
func adapterWith(l tenantLister, listerErr error) *Adapter {
	return &Adapter{
		loadCredential: func() (azcore.TokenCredential, error) { return nil, nil },
		newLister:      func(azcore.TokenCredential) (tenantLister, error) { return l, listerErr },
	}
}

func respErr(status int) error {
	return &azcore.ResponseError{StatusCode: status, ErrorCode: "Code"}
}

func TestAdapterResolvesHomeTenant(t *testing.T) {
	a := adapterWith(stubLister{tenants: []tenantInfo{
		{tenantID: "guest-tenant", displayName: "Guest Org"},
		{tenantID: "8d65815f-a5b6-402f-9298-045155da7d74", displayName: "Contoso", home: true},
	}}, nil)
	id, err := a.Resolve(context.Background(), model.Azure, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The Home tenant, not the first, is chosen; its display name is the
	// principal (the tenant, not a specific caller).
	if id.Provider != model.Azure || id.Account != "8d65815f-a5b6-402f-9298-045155da7d74" || id.Principal != "Contoso" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestAdapterFallsBackToFirstTenant(t *testing.T) {
	a := adapterWith(stubLister{tenants: []tenantInfo{
		{tenantID: "only", displayName: "Only Org"},
	}}, nil)
	id, err := a.Resolve(context.Background(), model.Azure, auth.Discovery)
	if err != nil || id.Account != "only" {
		t.Fatalf("no-home fallback failed: id=%+v err=%v", id, err)
	}
}

func TestAdapterNoTenantsFailsClosed(t *testing.T) {
	id, err := adapterWith(stubLister{tenants: nil}, nil).Resolve(context.Background(), model.Azure, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("empty tenant list did not fail closed: id=%+v err=%v", id, err)
	}
}

func TestAdapterClassifiesFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want auth.Kind
	}{
		{"401 unauthorized", respErr(http.StatusUnauthorized), auth.KindExpired},
		{"403 forbidden", respErr(http.StatusForbidden), auth.KindDenied},
		{"500 server error", respErr(http.StatusInternalServerError), auth.KindUnknown},
		{"plain error", errors.New("no credential in the chain"), auth.KindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := adapterWith(stubLister{err: tc.err}, nil).Resolve(context.Background(), model.Azure, auth.Discovery)
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

func TestAdapterCredentialFailureFailsClosed(t *testing.T) {
	a := &Adapter{
		loadCredential: func() (azcore.TokenCredential, error) {
			return nil, errors.New("DefaultAzureCredential: no credential available")
		},
		newLister: func(azcore.TokenCredential) (tenantLister, error) { return stubLister{}, nil },
	}
	id, err := a.Resolve(context.Background(), model.Azure, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("credential failure did not fail closed: id=%+v err=%v", id, err)
	}
}

func TestAdapterRejectsNonAzureProvider(t *testing.T) {
	id, err := adapterWith(stubLister{}, nil).Resolve(context.Background(), model.AWS, auth.Discovery)
	if err == nil || !id.IsZero() {
		t.Fatalf("adapter resolved a non-azure provider: id=%+v err=%v", id, err)
	}
}

// TestAdapterNeverLeaksTokenThroughError proves the no-leak guarantee at the
// adapter boundary: an ARM error whose message embeds a token must not surface
// the token, because the adapter routes every failure through auth.Fail.
func TestAdapterNeverLeaksTokenThroughError(t *testing.T) {
	token := "eyJ" + "0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" + ".eyJ" + "hdWQiOiJhcm0ifQ" + ".sig"
	armErr := &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "AuthorizationFailed with token " + token}
	_, err := adapterWith(stubLister{err: armErr}, nil).Resolve(context.Background(), model.Azure, auth.Discovery)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("adapter leaked the token: %q", err.Error())
	}
	if !strings.Contains(err.Error(), redact.Placeholder) {
		t.Errorf("adapter error was not scrubbed: %q", err.Error())
	}
}

// TestResolveCredentialReturnsIdentityAndCredentialFromOneLoad proves the seam
// the collectors rely on: resolveCredential loads the chain once and returns both
// the identity and that same credential, so the collector clients are built from
// the credential identity was established with.
func TestResolveCredentialReturnsIdentityAndCredentialFromOneLoad(t *testing.T) {
	calls := 0
	cred := fakeCred{id: "the-cred"}
	id, gotCred, err := countingAdapter(cred, &calls).resolveCredential(context.Background(), model.Azure, auth.Discovery)
	if err != nil {
		t.Fatalf("resolveCredential: %v", err)
	}
	if calls != 1 {
		t.Fatalf("loadCredential called %d times, want 1", calls)
	}
	if id.Account != "tenant-1" {
		t.Errorf("account = %q, want tenant-1", id.Account)
	}
	if gotCred != cred {
		t.Error("resolveCredential did not return the credential it resolved")
	}
}

// TestAdapterViaRegistry proves the adapter plugs into the production registry.
func TestAdapterViaRegistry(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(model.Azure, adapterWith(stubLister{tenants: []tenantInfo{
		{tenantID: "t1", displayName: "Org", home: true},
	}}, nil))
	id, err := reg.Resolve(context.Background(), model.Azure, auth.Discovery)
	if err != nil || id.Account != "t1" {
		t.Fatalf("registry resolve: id=%+v err=%v", id, err)
	}
}
