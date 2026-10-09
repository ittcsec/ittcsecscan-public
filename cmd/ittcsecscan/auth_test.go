package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

func errNoAccess() error { return errors.New("AccessDenied: not authorized") }

func errWithToken(token string) error {
	return fmt.Errorf("provider request failed with %s in the response", token)
}

// fakeResolver is a minimal auth.Resolver for the CLI tests. StubResolver is
// test-only inside package auth and not importable here, so the auth command's
// tests declare their own fake, exactly as the seam's design intends.
type fakeResolver struct {
	id  auth.Identity
	err error
}

func (f fakeResolver) Resolve(_ context.Context, p model.Provider, _ auth.Profile) (auth.Identity, error) {
	if f.err != nil {
		return auth.Identity{}, f.err
	}
	id := f.id
	id.Provider = p
	return id, nil
}

func noEnv(string) (string, bool) { return "", false }

// registryOf builds a registry from a provider->resolver map. Providers absent
// from the map have no adapter and fail closed, like production today.
func registryOf(m map[model.Provider]fakeResolver) *auth.Registry {
	r := auth.NewRegistry()
	for p, f := range m {
		r.Register(p, f)
	}
	return r
}

func resolvedFake(account string) fakeResolver {
	return fakeResolver{id: auth.Identity{Account: account, Principal: "principal-" + account}}
}

// TestAuthPlanEmptyRegistryFailsClosed is the production pre-adapter behaviour:
// with no adapters, every provider is auth-failed and the command exits 7, never
// 0.
func TestAuthPlanEmptyRegistryFailsClosed(t *testing.T) {
	res := invokeResolver(context.Background(), auth.NewRegistry(), noEnv, "auth", "plan")
	if res.code != exitcode.AuthFailed {
		t.Fatalf("empty registry exit = %d, want %d (auth-failed)\n%s", res.code, exitcode.AuthFailed, res.out)
	}
	for _, p := range model.Providers {
		if !strings.Contains(res.out, string(p)) {
			t.Errorf("output does not mention %s: %q", p, res.out)
		}
	}
	if !strings.Contains(res.out, "auth-failed") {
		t.Errorf("output does not report auth-failed: %q", res.out)
	}
}

// TestAuthPlanResolvedExitsZero: every provider resolving is the only way to
// exit 0.
func TestAuthPlanResolvedExitsZero(t *testing.T) {
	reg := registryOf(map[model.Provider]fakeResolver{
		model.AWS:             resolvedFake("aws-acct"),
		model.Azure:           resolvedFake("azure-sub"),
		model.GCP:             resolvedFake("gcp-proj"),
		model.GitHub:          resolvedFake("github-login"),
		model.GitLab:          resolvedFake("gitlab-login"),
		model.Kubernetes:      resolvedFake("https://k8s.example:443"),
		model.Okta:            resolvedFake("https://acme.okta.com"),
		model.GoogleWorkspace: resolvedFake("my_customer"),
		model.MCP:             resolvedFake("/home/u/.mcp.json"),
	})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan")
	if res.code != exitcode.OK {
		t.Fatalf("all resolved exit = %d, want 0\n%s", res.code, res.out)
	}
	if !strings.Contains(res.out, "resolved") || !strings.Contains(res.out, "aws-acct") {
		t.Errorf("output missing resolved identity: %q", res.out)
	}
}

// TestAuthPlanNeverPassesUnlessAllResolve sweeps every combination of the
// providers succeeding or failing, and asserts the command exits 0 only when all
// of them resolve. This is the never-pass invariant at the CLI boundary; a
// mutation that turns the aggregation into anything but "all must resolve"
// breaks it. The sweep covers one bit per provider so the all-resolve case is
// actually exercised as the provider set grows.
func TestAuthPlanNeverPassesUnlessAllResolve(t *testing.T) {
	fail := fakeResolver{err: errNoAccess()}
	for mask := 0; mask < (1 << len(model.Providers)); mask++ {
		m := map[model.Provider]fakeResolver{}
		allResolve := true
		for i, p := range model.Providers {
			if mask&(1<<i) != 0 {
				m[p] = resolvedFake(string(p))
			} else {
				m[p] = fail
				allResolve = false
			}
		}
		res := invokeResolver(context.Background(), registryOf(m), noEnv, "auth", "plan")
		wantOK := allResolve
		gotOK := res.code == exitcode.OK
		if gotOK != wantOK {
			t.Fatalf("mask %03b: exit=%d (ok=%v), want ok=%v\n%s", mask, res.code, gotOK, wantOK, res.out)
		}
		if !gotOK && res.code != exitcode.AuthFailed {
			t.Fatalf("mask %03b: failure exit=%d, want %d (auth-failed)", mask, res.code, exitcode.AuthFailed)
		}
	}
}

// TestAuthPlanRedactsTokenInOutput proves defence in depth at the CLI boundary:
// a resolver failure whose message embeds a token must not print the token,
// independent of the seam's own scrubbing.
func TestAuthPlanRedactsTokenInOutput(t *testing.T) {
	token := "ya29." + strings.Repeat("C", 40)
	reg := registryOf(map[model.Provider]fakeResolver{
		model.AWS: {err: errWithToken(token)},
	})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "aws")
	all := res.out + res.err
	if strings.Contains(all, token) {
		t.Fatalf("token leaked to command output: %q", all)
	}
	if !strings.Contains(res.out, redact.Placeholder) {
		t.Errorf("failure output was not redacted: %q", res.out)
	}
	if res.code != exitcode.AuthFailed {
		t.Errorf("exit = %d, want auth-failed", res.code)
	}
}

// TestAuthPlanAzureLabelsPrincipalAsTenant proves the Azure principal note
// surfaces in the output: a reader must not assume the principal names a
// specific user or service principal for Azure.
func TestAuthPlanAzureLabelsPrincipalAsTenant(t *testing.T) {
	reg := registryOf(map[model.Provider]fakeResolver{
		model.Azure: resolvedFake("tenant-id"),
	})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "azure")
	if res.code != exitcode.OK {
		t.Fatalf("exit = %d, want 0\n%s", res.code, res.out)
	}
	if !strings.Contains(res.out, "authenticated tenant") || !strings.Contains(res.out, "not a specific") {
		t.Errorf("azure output does not clarify the principal is the tenant: %q", res.out)
	}
}

// TestAuthPlanGCPEmptyAccountNote proves the empty-account clarification
// surfaces for GCP when the account is blank.
func TestAuthPlanGCPEmptyAccountNote(t *testing.T) {
	// resolvedFake sets Account to the given value; "" yields an empty account.
	reg := registryOf(map[model.Provider]fakeResolver{
		model.GCP: {id: auth.Identity{Account: "", Principal: "sa@example.com"}},
	})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "gcp")
	if res.code != exitcode.OK {
		t.Fatalf("exit = %d, want 0\n%s", res.code, res.out)
	}
	if !strings.Contains(res.out, "empty account") || !strings.Contains(res.out, "no associated default project") {
		t.Errorf("gcp empty-account note missing: %q", res.out)
	}
}

// TestAuthPlanGCPWithProjectHasNoNote confirms the note only appears when the
// account is empty.
func TestAuthPlanGCPWithProjectHasNoNote(t *testing.T) {
	reg := registryOf(map[model.Provider]fakeResolver{model.GCP: resolvedFake("my-project")})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "gcp")
	if strings.Contains(res.out, "empty account") {
		t.Errorf("gcp with a project wrongly showed the empty-account note: %q", res.out)
	}
}

// TestAuthPlanAwsHasNoTenantNote confirms the note is Azure-specific.
func TestAuthPlanAwsHasNoTenantNote(t *testing.T) {
	reg := registryOf(map[model.Provider]fakeResolver{model.AWS: resolvedFake("acct")})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "aws")
	if strings.Contains(res.out, "authenticated tenant") {
		t.Errorf("aws output wrongly carries the azure tenant note: %q", res.out)
	}
}

// TestAuthPlanSelectsSingleProvider checks --provider limits the plan.
func TestAuthPlanSelectsSingleProvider(t *testing.T) {
	reg := registryOf(map[model.Provider]fakeResolver{model.AWS: resolvedFake("only-aws")})
	res := invokeResolver(context.Background(), reg, noEnv, "auth", "plan", "--provider", "aws")
	if res.code != exitcode.OK {
		t.Fatalf("exit = %d, want 0\n%s", res.code, res.out)
	}
	if strings.Contains(res.out, "azure") || strings.Contains(res.out, "gcp") {
		t.Errorf("single-provider plan mentioned others: %q", res.out)
	}
}

// TestAuthPlanRejectsBadFlags: unknown provider and profile are usage errors,
// not auth failures.
func TestAuthPlanRejectsBadFlags(t *testing.T) {
	reg := auth.NewRegistry()
	for _, args := range [][]string{
		{"auth", "plan", "--provider", "oracle"},
		{"auth", "plan", "--profile", "root"},
	} {
		res := invokeResolver(context.Background(), reg, noEnv, args...)
		if res.code != exitcode.Usage {
			t.Errorf("%v exit = %d, want %d (usage)", args, res.code, exitcode.Usage)
		}
	}
}

// TestAuthUnknownSubcommand is a usage error.
func TestAuthUnknownSubcommand(t *testing.T) {
	res := invokeResolver(context.Background(), auth.NewRegistry(), noEnv, "auth", "verify")
	if res.code != exitcode.Usage {
		t.Errorf("exit = %d, want usage", res.code)
	}
}

// TestAuthPlanCancelledContextInterrupts: an interrupt stops the command as an
// interrupt (130), not as an auth failure (7).
func TestAuthPlanCancelledContextInterrupts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := invokeResolver(ctx, auth.NewRegistry(), noEnv, "auth", "plan")
	if res.code != exitcode.Interrupted {
		t.Fatalf("cancelled exit = %d, want %d (interrupted)", res.code, exitcode.Interrupted)
	}
}
