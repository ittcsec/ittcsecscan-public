// Package rules is the deterministic detection-pack rule engine (ADR-0021,
// concretizing ADR-0004). It evaluates declarative rules from signed packs against the
// canonical evidence graph (internal/collect) and produces findings whose state,
// confidence, and explanation are a pure, reproducible function of the collected
// evidence.
//
// Invariants this package upholds, structurally (ADR-0021 §3-4):
//   - Evaluation is deterministic: a rule is closed predicate DATA with no call site,
//     so it cannot reach the network, an AI model, the clock, or randomness; every
//     iteration is sorted, so identical inputs give byte-identical findings in
//     identical order. The evaluation packages are additionally held to a
//     read-only-of-the-world import gate (deterministic.go), the sibling of
//     internal/collect/readonly.go.
//   - Pack content is declarative and signed; untrusted pack code is never executed,
//     and rules have no shell or network access.
//   - Outcomes are pass, fail, unknown, error, or not-applicable, and unknown / error /
//     not-applicable are never converted to pass. Honest state is enforced by the
//     engine from the scan's completeness records (ADR-0021 §5), not by each rule: a
//     pass or fail is produced only when every declared completeness input is Complete;
//     a Denied / Partial / Errored input yields unknown; an Unsupported or absent input
//     yields not-applicable; a gap is never silent.
//   - Every finding carries the nodes, edges, and facts it was derived from and a
//     deterministic, documented confidence basis, so it is auditable back to raw
//     evidence.
package rules
