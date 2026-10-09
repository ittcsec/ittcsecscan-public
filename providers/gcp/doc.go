// Package gcp is the GCP credential-chain adapter. It resolves the scanner's GCP
// identity through Application Default Credentials and returns a non-secret
// auth.Identity; it holds, stores, and returns no credential material beyond the
// short-lived access token it transmits to the token-introspection endpoint,
// which it never logs or returns.
//
// It is the only place in the product that imports the GCP client libraries
// (ADR-0016 §1, ADR-0017): the seam (internal/auth) and the rest of the core
// stay SDK-free, and depguard enforces that boundary. The read-only collectors
// live under providers/gcp/collect and read the REST APIs with plain HTTP.
//
// Collection OAuth scope, and how read-only is enforced: the identity probe
// (auth plan) requests only the userinfo.email scope, so it stays
// least-privilege. A scan additionally requests the broad cloud-platform scope
// for collection, because the first collected read, IAM
// projects.serviceAccounts.list, accepts no read-only-named scope (only
// cloud-platform or the iam scope; Google IAM API reference, verified
// 2026-09-18). The OAuth scope is an upper bound on what a token could do; it is
// the credential's granted IAM permissions, pinned to read-only operations in the
// discovery permission template (for example iam.serviceAccounts.list), that make
// the collection read-only, not the scope. The scope is broad; the permissions
// are not. This caveat is stated for the operator in permissions/README.md and
// docs/cli.md as well.
//
// Identity call: OAuth 2.0 token introspection at oauth2.googleapis.com/tokeninfo
// via google.golang.org/api/oauth2/v2, verified against the Google Cloud
// authentication documentation on 2026-09-17. Introspection needs no IAM
// permission; the principal's email is returned only when the token carries the
// https://www.googleapis.com/auth/userinfo.email scope, which this adapter
// requests. Unlike Azure, GCP returns the specific principal (a user or service
// account email), so Principal names the caller.
//
// The identity's Account is the credential's associated GCP project, from
// Application Default Credentials. It may be EMPTY: a user credential without a
// configured default project has no associated project, in which case the
// account is reported empty and the principal is still identified. Finding the
// projects such a credential can actually reach needs an IAM permission and
// belongs to the collectors, not the zero-permission identity probe.
//
// Provider semantics (resource hierarchy inheritance, IAM deny policies,
// conditions, service account impersonation) must come from official Google
// Cloud documentation and live access-denied tests, never from assumption.
package gcp
