// Package update implements "ittcsecscan update" on The Update Framework
// principles for the binary, collectors, packs, schemas, mappings, and threat
// intelligence.
//
// It verifies signed JSON metadata in four roles (root, timestamp, snapshot,
// targets) with threshold Ed25519 signatures, using the shared in-process
// verifier internal/sshsig and no new dependency (ADR-0030). The trust engine
// (metadata.go, verify.go) is transport-agnostic: it takes a Fetcher, so it runs
// the same way over HTTPS or an offline bundle. Installation is atomic with a
// retained last-known-good (install.go).
//
// Invariants this package upholds:
//   - Updates come only from trusted, signed metadata; never from an unsigned
//     or mutable "latest" URL.
//   - Rollback, freeze, mix-and-match, and arbitrary-installation attacks are
//     rejected; installation is atomic with last-known-good recovery.
//   - Update checks never transmit customer inventory or credentials.
package update
