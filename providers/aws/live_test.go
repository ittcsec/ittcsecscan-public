//go:build live

// This file builds only under the "live" tag, so CI (which never holds cloud
// credentials) does not compile or run it. It is the maintainer-run live
// verification required by ADR-0016 §3.
//
// Run it against the disposable AWS test account with credentials in the
// environment or a named profile:
//
//	AWS_PROFILE=ittcsecscan-test go test -tags live -run TestLive -v ./providers/aws/
//
// Set ITTCSECSCAN_LIVE_AWS_ACCOUNT to the expected account id to assert it; the
// account id is not committed to the repository.
package aws

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveGetCallerIdentity resolves the real AWS identity through the default
// credential chain and prints it. It proves the adapter authenticates end to
// end against the live test account.
func TestLiveGetCallerIdentity(t *testing.T) {
	id, err := New().Resolve(context.Background(), model.AWS, auth.Discovery)
	if err != nil {
		t.Fatalf("live resolve failed: %v", err)
	}
	if id.Account == "" || id.Principal == "" {
		t.Fatalf("live identity is incomplete: %+v", id)
	}
	if want := os.Getenv("ITTCSECSCAN_LIVE_AWS_ACCOUNT"); want != "" && id.Account != want {
		t.Fatalf("resolved account %s, want %s", id.Account, want)
	}
	t.Logf("live AWS identity: account=%s principal=%s", id.Account, id.Principal)
}

// TestLiveDeniedActionIsNotAPass verifies the never-pass contract against the
// real account: sts:GetCallerIdentity itself needs no permission, so this
// confirms that a genuinely unauthorized STS call (assuming a role the
// read-only test user cannot assume) surfaces as a failure, never a resolved
// identity. It is skipped unless a forbidden role ARN is supplied.
func TestLiveDeniedActionIsNotAPass(t *testing.T) {
	roleARN := os.Getenv("ITTCSECSCAN_LIVE_AWS_FORBIDDEN_ROLE")
	if roleARN == "" {
		t.Skip("set ITTCSECSCAN_LIVE_AWS_FORBIDDEN_ROLE to a role the test user may not assume")
	}
	// Left to the step-3 template verification to exercise fully; this scaffold
	// records the intent so the maintainer-run suite has a home for it.
	t.Skip("access-denied verification lands with the least-privilege templates (step 3)")
}
