package auth

import (
	"context"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// StubResolver is a deterministic, offline Resolver for tests. It performs no
// network I/O and wraps no SDK, so the seam's invariants can be exercised before
// any provider adapter exists.
//
// It lives in a _test.go file on purpose. A resolver that returns a fake
// successful identity would be dangerous if it could ever run in production, so
// the guarantee is compile-time: test files are never linked into a non-test
// build, and any production reference to StubResolver is a build error. The real
// AWS, Azure, and GCP adapters arrive under ADR-0017 (SDK intake) and delegate
// to the native credential chains; other packages' tests declare their own
// small auth.Resolver fakes rather than importing this one.
//
// Each provider maps to one Outcome. A provider with no configured Outcome
// resolves as KindUnknown, so an unconfigured stub also fails closed.
type StubResolver struct {
	Outcomes map[model.Provider]Outcome
}

// Outcome is what a StubResolver returns for one provider. A nil Fail means the
// resolution succeeds and returns Identity; a non-nil Fail means it fails with
// that failure's Kind and cause, and Identity is ignored.
type Outcome struct {
	Identity Identity
	Fail     *stubFail
}

// stubFail describes a stubbed failure. Cause may embed token-shaped material so
// a test can prove that material never escapes the seam; the seam scrubs and
// drops it.
type stubFail struct {
	Kind  Kind
	Cause error
}

// Resolve implements Resolver.
func (s StubResolver) Resolve(ctx context.Context, p model.Provider, prof Profile) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, fail(p, prof, KindUnknown, err)
	}
	o, ok := s.Outcomes[p]
	if !ok {
		return Identity{}, fail(p, prof, KindUnknown, errNoStubOutcome)
	}
	if o.Fail != nil {
		return Identity{}, fail(p, prof, o.Fail.Kind, o.Fail.Cause)
	}
	return o.Identity, nil
}

// errNoStubOutcome is returned when a provider has no configured Outcome.
var errNoStubOutcome = stubError("no stub outcome configured for provider")

type stubError string

func (e stubError) Error() string { return string(e) }
