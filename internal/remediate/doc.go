// Package remediate produces remediation plans, simulates them, and, behind an
// experimental build tag and explicit approval, applies and verifies them.
//
// This package is the plan generator: plan-only, read-only, and deterministic
// (enforced by deterministic.go), so a plan's PlanHash is stable and an approval
// can bind to it. Guidance comes only from the in-code, doc-verified template
// catalog (catalog.go); a finding type with no verified template yields an
// honest named gap, never a fabricated action.
//
// The executor (the one component allowed to make provider changes) lives in the
// execute subpackage and is compiled only under the remediation build tag
// (docs/adr/0029-safe-remediation-and-verification.md).
//
// Invariants this package upholds:
//   - Nothing is executed without an immutable plan (current-state hash,
//     actions, preconditions, privilege, side effects, verification, rollback)
//     and an approval bound to the exact plan hash.
//   - Remediation uses a separate credential profile from scanning.
//   - Provider changes are made through SDK calls, never shell interpolation.
//   - State is re-read immediately before applying; drift stops execution.
package remediate
