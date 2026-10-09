// Package azure is the Azure credential-chain adapter. It resolves the scanner's
// Azure identity through DefaultAzureCredential and returns a non-secret
// auth.Identity; it holds, stores, and returns no credential material.
//
// It is the only place in the product that imports the Azure SDK (ADR-0016 §1,
// ADR-0017): the seam (internal/auth) and the rest of the core stay SDK-free,
// and depguard enforces that boundary. Collectors and their read-only permission
// declarations arrive in a later milestone.
//
// Identity call: the ARM Tenants - List operation
// (GET https://management.azure.com/tenants), verified against the Azure REST
// API reference on 2026-09-17. It needs no RBAC role, performs no write, and
// returns the tenants the credential can see. Azure has no single call that also
// returns the calling user or service principal without additional permission,
// so this adapter reports the authenticated tenant as the identity's account and
// its display name as the principal, labelled as the tenant. Identifying the
// specific calling principal needs more permission and arrives with the collectors.
//
// Provider semantics (RBAC inheritance, deny assignments, PIM eligibility,
// Conditional Access) must come from official Microsoft documentation and live
// access-denied tests, never from assumption.
package azure
