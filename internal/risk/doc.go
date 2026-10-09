// Package risk scores findings and attack paths with a transparent, versioned
// model that keeps exploitability, exposure, privilege, business impact, blast
// radius, threat relevance, and evidence confidence separate.
//
// Implemented in a later milestone (ADR-0027): a versioned weight table with a visible
// per-score basis, composing severity, evidence confidence, exposure, and business
// impact; the reserved dimensions (exploitability, blast radius, threat relevance)
// are weighted zero until an honest signal exists.
//
// Invariants this package must uphold:
//   - Weights and caps are documented and versioned; no opaque multiplication.
//   - Customer risk appetite and asset criticality adjust priority without
//     changing observed facts.
package risk
