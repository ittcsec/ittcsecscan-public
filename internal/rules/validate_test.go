package rules

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestValidateRejectsMalformed proves a rule that is malformed or invents vocabulary is
// refused before evaluation: unknown operator, unknown node type, unknown edge kind, no
// completeness contract, and a bad numeric comparator each fail Validate.
func TestValidateRejectsMalformed(t *testing.T) {
	base := publicStorageRule()
	cases := []struct {
		name string
		mut  func(*Rule)
	}{
		{"no id", func(r *Rule) { r.ID = "" }},
		{"no version", func(r *Rule) { r.Version = "" }},
		{"unknown node type", func(r *Rule) { r.Selector.NodeType = model.NodeType("not_a_type") }},
		{"unknown operator", func(r *Rule) { r.Predicate = Predicate{Op: Op("frobnicate"), Fact: "x"} }},
		{"no completeness contract", func(r *Rule) { r.Requires.Completeness = nil }},
		{"unknown required node", func(r *Rule) { r.Requires.Nodes = []model.NodeType{"nope"} }},
		{"unknown required edge", func(r *Rule) { r.Requires.Edges = []model.EdgeKind{"nope"} }},
		{"has_edge no target", func(r *Rule) { r.Predicate = Predicate{Op: OpHasEdge, Edge: model.EdgeAssumes} }},
		{"has_edge unknown edge", func(r *Rule) {
			r.Predicate = Predicate{Op: OpHasEdge, Edge: "nope", Target: &Selector{NodeType: model.NodeRole}}
		}},
		{"fact_num bad cmp", func(r *Rule) { r.Predicate = Predicate{Op: OpFactNum, Fact: "x", Cmp: "approximately"} }},
		{"and no children", func(r *Rule) { r.Predicate = Predicate{Op: OpAnd} }},
		{"not two children", func(r *Rule) {
			r.Predicate = Predicate{Op: OpNot, Children: []Predicate{{Op: OpFactPresent, Fact: "a"}, {Op: OpFactPresent, Fact: "b"}}}
		}},
	}
	for _, c := range cases {
		r := base
		c.mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate accepted an invalid rule", c.name)
		}
	}
}

// TestValidateAcceptsWellFormed proves the representative rules validate.
func TestValidateAcceptsWellFormed(t *testing.T) {
	for _, r := range []Rule{publicStorageRule(), rotationRule()} {
		if err := r.Validate(); err != nil {
			t.Errorf("well-formed rule %s rejected: %v", r.ID, err)
		}
	}
}

// TestEvaluateRejectsInvalidRule proves the engine refuses an invalid rule rather than
// evaluating it (defence in depth beside pack-load validation).
func TestEvaluateRejectsInvalidRule(t *testing.T) {
	bad := publicStorageRule()
	bad.Requires.Completeness = nil
	if _, err := Evaluate(nil, []Rule{bad}); err == nil {
		t.Error("Evaluate ran an invalid rule")
	}
}
