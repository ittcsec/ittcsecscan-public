// Package auth is the provider-neutral credential seam: it resolves who the
// scanner authenticates as against a cloud provider, without ever holding,
// storing, or returning credential material.
//
// The product owns no credential. A concrete resolver (AWS, Azure, GCP; a later
// pull request under ADR-0017) delegates to that provider's native credential
// chain and returns only a non-secret Identity. This package defines the seam
// and its two safety invariants; StubResolver (stub.go) implements it offline so
// those invariants are built and proven before any SDK exists.
//
// Two invariants, tested adversarially:
//
//   - Fail closed. Resolution succeeds only when it returns a populated Identity
//     and a nil error. Every failure, including an unclassified or collection
//     error, returns the zero Identity and a non-nil *Error. An unknown or
//     denied result is never turned into a pass (the project's safety invariants). The CLI
//     maps any *Error to exit code 7 (auth-failed); that wiring lands with the
//     auth-plan and doctor work.
//   - No leak. An *Error never carries credential material. The underlying cause
//     is scrubbed through redact.String at construction and then dropped, so no
//     Unwrap can reach a token that was embedded in it, and every rendering of
//     the error is already redacted. Defence in depth: the logging handler
//     scrubs again.
package auth

import (
	"context"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// Profile is a least-privilege credential profile (ADR-0005, ADR-0016 §3). The
// scanner authenticates under exactly one. Discovery and DeepEvidence are
// read-only; Remediation is separate and never the default, and no code in this
// phase exercises it.
type Profile string

const (
	Discovery    Profile = "discovery"
	DeepEvidence Profile = "deep-evidence"
	Remediation  Profile = "remediation"
)

// Profiles lists every profile, in privilege order.
var Profiles = []Profile{Discovery, DeepEvidence, Remediation}

// Valid reports whether p is a known profile.
func (p Profile) Valid() bool {
	for _, q := range Profiles {
		if p == q {
			return true
		}
	}
	return false
}

// Identity is the non-secret result of a successful resolution: who the scanner
// authenticated as. It holds no credential material. Account and Principal are
// not secrets (an account id or an ARN is not sensitive within the tenant). A
// reflection test forbids any byte-slice, Secret, or token-shaped field here,
// mirroring ADR-0014 §4.
type Identity struct {
	Provider model.Provider // which provider this identity is for
	// Account is the provider's top-level identity anchor: the AWS account id,
	// the Azure tenant id, or the GCP project. For GCP it MAY be empty: a
	// credential with no associated default project has no project here, and the
	// principal is still identified. A reader must not treat an empty account as
	// an error or assume every credential has a project.
	Account string
	// Principal names the caller. For AWS it is the caller ARN (a specific user
	// or role). For Azure it is the authenticated tenant's display name, NOT a
	// specific user or service principal: Azure does not reveal the calling
	// principal at the zero-permission identity call, and identifying it needs
	// additional permission that may arrive with the collectors. A reader
	// (a report, a permission-template decision) must not assume Principal always
	// names a specific identity.
	Principal string
}

// IsZero reports whether id carries no identity, i.e. resolution did not
// succeed. A resolved Identity always names a provider.
func (id Identity) IsZero() bool { return id == Identity{} }

// Kind classifies why authentication did not resolve. The zero value is
// KindUnknown, so a path that fails to classify still fails closed as unknown,
// never as success.
type Kind int

const (
	// KindUnknown is any unclassified or collection failure: a missing or
	// malformed configuration, a network error, an unexpected provider response.
	// It is the safe default and is never a pass.
	KindUnknown Kind = iota
	// KindExpired means the credential chain produced an expired or otherwise
	// invalid token.
	KindExpired
	// KindDenied means an identity or API call was refused (for example
	// AccessDenied): the caller authenticated but lacks the permission, or the
	// identity could not be established.
	KindDenied
)

// String names the kind for diagnostics.
func (k Kind) String() string {
	switch k {
	case KindExpired:
		return "expired"
	case KindDenied:
		return "denied"
	default:
		return "unknown"
	}
}

// Error is the sole failure type returned by a Resolver. It records the
// provider, profile, and a fail-closed Kind, plus a message that has already
// been scrubbed. It deliberately does not implement Unwrap: the raw cause is not
// retained, so an error chain cannot be walked back to a token.
type Error struct {
	Provider model.Provider
	Profile  Profile
	Kind     Kind
	msg      string // already passed through redact.String; may be empty
}

// Error implements error. The rendered string is redaction-safe.
func (e *Error) Error() string {
	if e.msg == "" {
		return fmt.Sprintf("auth %s/%s: %s", e.Provider, e.Profile, e.Kind)
	}
	return fmt.Sprintf("auth %s/%s: %s: %s", e.Provider, e.Profile, e.Kind, e.msg)
}

// Fail builds the failure a credential adapter returns: a non-resolved *Error
// with the given Kind, whose cause is scrubbed and then dropped so no token can
// survive in it. Adapters in other packages (which cannot reach the unexported
// constructor) must route every failure through Fail rather than returning a
// raw SDK error, so the no-leak guarantee holds at the seam, not only at the
// CLI boundary.
func Fail(p model.Provider, prof Profile, kind Kind, cause error) error {
	return fail(p, prof, kind, cause)
}

// fail builds a non-resolved *Error. The cause is scrubbed through
// redact.String and then discarded, so the Error never retains raw credential
// material. Concrete resolvers must route every failure through this
// constructor rather than returning a provider error directly.
func fail(p model.Provider, prof Profile, kind Kind, cause error) *Error {
	msg := ""
	if cause != nil {
		msg = redact.String(cause.Error())
	}
	return &Error{Provider: p, Profile: prof, Kind: kind, msg: msg}
}

// Resolver authenticates the scanner as the caller for a provider under a
// profile. It performs no cloud write and retrieves no secret value.
//
// The contract, which callers may rely on and which the tests enforce:
//
//   - On success: a populated Identity and a nil error.
//   - On any failure: the zero Identity and a non-nil error, always an *Error.
//   - Never a populated Identity with a non-nil error, and never the zero
//     Identity with a nil error.
type Resolver interface {
	Resolve(ctx context.Context, p model.Provider, prof Profile) (Identity, error)
}
