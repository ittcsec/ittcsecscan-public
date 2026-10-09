package rules

import "github.com/ittcsec/ittcsecscan/internal/model"

// Grounding is the raw evidence a finding is derived from, so every finding is
// auditable back to what the collectors saw (ADR-0021 §6). Each slice is ordered
// deterministically. Nodes and Edges are canonical ids and endpoint descriptions;
// Facts are the exact key=value pairs the predicate matched; Completeness are the
// service:status records the engine consulted to decide the state.
type Grounding struct {
	Nodes        []string `json:"nodes,omitempty"`
	Edges        []string `json:"edges,omitempty"`
	Facts        []string `json:"facts,omitempty"`
	Completeness []string `json:"completeness,omitempty"`
}

// Result is one rule's outcome for one entity: the engine's native finding, produced
// before persistence (the store maps EntityID, a canonical NativeID, to a tenant-scoped
// model.StableID, and the report layer renders Explanation). State is a model.Outcome;
// unknown, error, and not-applicable are never reported as pass (ADR-0004). Confidence
// is the deterministic evidential support for State, with its factors named in Basis
// and the derivation in Trace.
type Result struct {
	Rule       model.RuleRef    `json:"rule"`
	EntityID   string           `json:"entity_id"`
	EntityType model.NodeType   `json:"entity_type,omitempty"`
	State      model.Outcome    `json:"state"`
	Confidence model.Confidence `json:"confidence"`
	Basis      []string         `json:"confidence_basis,omitempty"`
	Grounding  Grounding        `json:"grounding"`
	Trace      []string         `json:"trace"`
	Detail     string           `json:"detail,omitempty"`
}
