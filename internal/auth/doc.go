// Package auth adapts the native AWS, Azure, and GCP credential chains into
// short-lived, scoped clients and plans the least-privilege permissions each
// collector requires.
//
// Status: not implemented.
//
// Invariants this package must uphold:
//   - Credentials are never persisted, cached to disk, or logged. Values that
//     must be held in memory are wrapped in redact.Secret.
//   - No proprietary secret vault: access always comes from the provider's
//     native chain (environment, workload identity, OIDC federation, managed
//     identity, CLI profiles).
//   - Discovery, deep-evidence, and remediation profiles are separate; the
//     default profile is read-only.
//   - Overbroad scanner permissions are detected and reported, never silently
//     used.
package auth
