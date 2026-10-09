// Package normalize converts a collected scan (internal/collect) into the
// canonical model graph (internal/model): entities, edges, and evidence keyed
// by tenant-scoped StableID. It is the analysis substrate every engine reads,
// so no engine reads the raw collected graph (ADR-0023).
//
// It depends on internal/collect, internal/model, and internal/repo only, never
// on internal/store: the StableID keying is borrowed from the open tenant
// through a repo interface, so the store keeps the HMAC key (ADR-0014 §4).
//
// Invariants this package upholds:
//   - Provenance is preserved at the granularity the collectors record: every
//     envelope is carried through as model.Evidence, and an edge references the
//     envelopes whose resource scope matches an endpoint native id. No per-object
//     link is fabricated where the collectors recorded none (ADR-0023 §3, NZ-1).
//   - Provider semantics are never invented. An attribute the collector did not
//     set is absent; a gap it recorded stays a gap in the carried completeness.
//   - The transform is deterministic: identical input yields identical, stably
//     ordered output.
package normalize
