// Package aws is the AWS credential-chain adapter. It resolves the scanner's AWS
// identity through the SDK's default credential chain and returns a non-secret
// auth.Identity; it holds, stores, and returns no credential material.
//
// It is the only place in the product that imports the AWS SDK (ADR-0016 §1,
// ADR-0017): the seam (internal/auth) and the rest of the core stay SDK-free,
// and depguard enforces that boundary. Collectors and their read-only permission
// declarations arrive in a later milestone.
//
// Provider semantics (policy evaluation, SCPs, permission boundaries, session
// policies) must come from official AWS documentation and live access-denied
// tests, never from assumption. The identity call, sts:GetCallerIdentity, was
// verified against the AWS STS API reference on 2026-09-17: it needs no IAM
// permission and performs no write.
package aws
