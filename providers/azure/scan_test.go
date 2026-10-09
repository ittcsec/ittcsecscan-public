package azure

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// fakeCred is a no-op TokenCredential standing in for a resolved credential, so a
// test can assert the same credential flows from resolution into the collectors
// without a real token, network, or SDK. It is comparable so a test can check the
// exact credential is threaded through.
type fakeCred struct{ id string }

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token"}, nil
}

// countingAdapter builds an Adapter with a counting credential load and a stub
// tenant lister, so resolution is hermetic and loadCredential calls can be
// counted.
func countingAdapter(cred azcore.TokenCredential, calls *int) *Adapter {
	return &Adapter{
		loadCredential: func() (azcore.TokenCredential, error) { *calls++; return cred, nil },
		newLister: func(azcore.TokenCredential) (tenantLister, error) {
			return stubLister{tenants: []tenantInfo{{tenantID: "tenant-1", displayName: "Contoso", home: true}}}, nil
		},
	}
}

// TestSourceCollectorsResolveCredentialOnceNotOncePerScope is the regression
// guard for the single-resolution guarantee, stated for the Azure case
// explicitly so a future reader does not mistake the differing token scopes for
// the guarantee having weakened.
//
// Azure's identity call draws an ARM (management) token and the Entra collector
// draws a Microsoft Graph token: those are DIFFERENT SCOPES. The guarantee is
// that the CREDENTIAL is resolved exactly once, not that every call uses one
// scope. Two scopes drawn from one credential still means the reported identity
// and the collection cannot come from two different resolutions, which across a
// token rotation could otherwise report one principal while collecting as
// another. So this asserts loadCredential is called exactly once, even though
// identity and collection use two scopes.
func TestSourceCollectorsResolveCredentialOnceNotOncePerScope(t *testing.T) {
	calls := 0
	s := &Source{adapter: countingAdapter(fakeCred{}, &calls)}

	account, collectors, err := s.Collectors(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collectors: %v", err)
	}
	if calls != 1 {
		t.Fatalf("loadCredential called %d times; one resolution must serve both the ARM-scoped identity call and the Graph-scoped collection", calls)
	}
	if account != "tenant-1" {
		t.Errorf("account = %q, want tenant-1", account)
	}
	if len(collectors) == 0 {
		t.Error("no collectors built")
	}
	if s.Provider() != model.Azure {
		t.Errorf("provider = %q, want azure", s.Provider())
	}
}

// TestSourceCollectorsPropagatesAuthFailure proves an authentication failure is
// surfaced as an error, never as an empty (and therefore silently clean) set of
// collectors.
func TestSourceCollectorsPropagatesAuthFailure(t *testing.T) {
	s := &Source{adapter: adapterWith(stubLister{err: respErr(403)}, nil)}
	if _, _, err := s.Collectors(context.Background(), nil); err == nil {
		t.Fatal("Collectors: want an error on auth failure, got nil")
	}
}
