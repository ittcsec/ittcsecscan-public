package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestApplyOverridesLastWins proves overrides set entity.Criticality and materialize
// provenance facts, with the last override for an entity winning (input is oldest
// first, matching the store's append order), and non-overridden entities left
// untouched. The engine uses input order, never a wall clock (At is unused here), so
// this package stays clock-free under the determinism gate.
func TestApplyOverridesLastWins(t *testing.T) {
	g := norm(&collect.Scan{Nodes: []collect.Node{
		node(model.NodeDataStore, "arn:aws:s3:::a", nil),
		node(model.NodeDataStore, "arn:aws:s3:::b", nil),
	}})
	overrides := []model.CriticalityOverride{
		{Entity: sid("arn:aws:s3:::a"), Criticality: 3, Actor: "alice", Reason: "prod"},
		{Entity: sid("arn:aws:s3:::a"), Criticality: 7, Actor: "bob", Reason: "raised"},
	}
	ApplyOverrides(g, overrides)

	a := entAttr(g, "arn:aws:s3:::a")
	if a["business_criticality"] != "7" || a["criticality_override_actor"] != "bob" || a["criticality_override_reason"] != "raised" {
		t.Errorf("last override should win: %+v", a)
	}
	// Entity.Criticality field is set too.
	for _, e := range g.Entities {
		if e.ID == sid("arn:aws:s3:::a") && e.Criticality != 7 {
			t.Errorf("Entity.Criticality = %d, want 7", e.Criticality)
		}
		if e.ID == sid("arn:aws:s3:::b") {
			if e.Criticality != 0 || e.Attributes["business_criticality"] != "" {
				t.Errorf("non-overridden entity was touched: crit=%d attrs=%+v", e.Criticality, e.Attributes)
			}
		}
	}
}

// TestApplyOverridesNoOp proves an empty override set changes nothing.
func TestApplyOverridesNoOp(t *testing.T) {
	g := norm(&collect.Scan{Nodes: []collect.Node{
		node(model.NodeDataStore, "arn:aws:s3:::a", map[string]string{"region": "us-east-1"}),
	}})
	ApplyOverrides(g, nil)
	a := entAttr(g, "arn:aws:s3:::a")
	if a["business_criticality"] != "" {
		t.Errorf("no overrides should change nothing: %+v", a)
	}
}
