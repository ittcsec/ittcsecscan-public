// Package graph computes effective reachability, effective permissions, attack
// paths, toxic combinations, and constrained minimum-cut remediation sets over the
// canonical model graph (internal/normalize).
//
// Implemented so far (ADR-0022 Layer B): name-level authorization *reachability and
// trust* (Reach): transitive principal to role/group reachability and external,
// public, and federated trust exposure. This is deliberately NOT effective
// permissions: it never asserts an action or an allow/deny, never produces a
// model.Permission, and every edge it emits is reachability or trust, labeled as
// such. Action-level effective permissions wait on the authorization-collection
// expansion (ADR-0022 Layer A); internet reachability is the reachability engine.
//
// Invariants this package upholds:
//   - Algorithms are reproducible: identical input yields identical, stably ordered
//     output. Enforced structurally by a determinism gate (deterministic.go), the
//     sibling of internal/rules/deterministic.go: no network, host, clock, or
//     randomness in the analysis path.
//   - Edges are never produced from unexplained inferred relationships; every
//     derived edge carries a reason trace back to the collected edges it came from.
//   - Deny is never assumed: Layer B has no deny data, so every derived edge records
//     deny as unevaluated, and a gap in the collected identity reads makes the
//     reachability an explicit floor, never an asserted-exhaustive result.
package graph
