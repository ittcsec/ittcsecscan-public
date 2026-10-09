package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func path(entry, target string, score int, steps ...model.PathStep) model.AttackPath {
	return model.AttackPath{Entry: model.StableID(entry), Target: model.StableID(target), Score: score, Confidence: 100, Steps: steps}
}

func step(node string, via model.EdgeKind) model.PathStep {
	return model.PathStep{Node: model.StableID(node), Via: via}
}

// TestCutsSeversSharedEdge proves an edge on several paths is one cut that removes
// all of them (PathsRemoved counts the severed paths).
func TestCutsSeversSharedEdge(t *testing.T) {
	paths := []model.AttackPath{
		path("eA", "Y", 10, step("eA", ""), step("X", model.EdgeAssumes), step("Y", model.EdgeTrusts)),
		path("eB", "Y", 10, step("eB", ""), step("X", model.EdgeAssumes), step("Y", model.EdgeTrusts)),
	}
	cuts := Cuts(paths)
	var shared *model.CutSet
	for i := range cuts {
		c := cuts[i].Changes[0]
		if c.Source == "X" && c.Target == "Y" && c.Kind == model.EdgeTrusts {
			shared = &cuts[i]
		}
	}
	if shared == nil {
		t.Fatalf("no cut for the shared X->Y trust edge: %+v", cuts)
	}
	if shared.PathsRemoved != 2 {
		t.Errorf("shared edge PathsRemoved = %d, want 2", shared.PathsRemoved)
	}
}

// TestCutsRankedByLeverageNotPathCount is the master-plan discipline: cuts rank by
// risk reduction against effort, never by raw path count. A low-effort change that
// severs one high-value path must outrank a high-effort change that severs many
// low-value ones.
func TestCutsRankedByLeverageNotPathCount(t *testing.T) {
	paths := []model.AttackPath{
		// Three low-value paths all crossing one high-effort trust edge X->Y.
		path("eA", "Y", 10, step("eA", ""), step("X", model.EdgeAssumes), step("Y", model.EdgeTrusts)),
		path("eB", "Y", 10, step("eB", ""), step("X", model.EdgeAssumes), step("Y", model.EdgeTrusts)),
		path("eC", "Y", 10, step("eC", ""), step("X", model.EdgeAssumes), step("Y", model.EdgeTrusts)),
		// One high-value path across a low-effort membership edge P->Q.
		path("P", "Q", 100, step("P", ""), step("Q", model.EdgeMemberOf)),
	}
	cuts := Cuts(paths)
	if len(cuts) == 0 {
		t.Fatal("expected cuts")
	}
	top := cuts[0].Changes[0]
	if top.Source != "P" || top.Target != "Q" || top.Kind != model.EdgeMemberOf {
		t.Errorf("top cut = %+v (risk %d, paths %d); a low-effort high-value cut should outrank a high-effort many-path cut, not raw path count",
			top, cuts[0].RiskReduction, cuts[0].PathsRemoved)
	}
	// The shared trust edge severs 3 paths but must not rank first (lower leverage).
	for i, c := range cuts {
		if c.Changes[0].Kind == model.EdgeTrusts && i == 0 {
			t.Error("the 3-path trust cut ranked first; ranking must weigh effort, not count")
		}
	}
}

func TestCutsEmpty(t *testing.T) {
	if got := Cuts(nil); len(got) != 0 {
		t.Errorf("no paths should yield no cuts: %+v", got)
	}
	// A single-node path (entry only, no hop) has no removable edge.
	if got := Cuts([]model.AttackPath{path("e", "e", 100, step("e", ""))}); len(got) != 0 {
		t.Errorf("an entry-only path has no edge to cut: %+v", got)
	}
}

func TestChangeCostDeterministic(t *testing.T) {
	e1, d1 := changeCost(model.EdgeTrusts)
	e2, d2 := changeCost(model.EdgeMemberOf)
	if e1 <= e2 || d1 <= d2 {
		t.Errorf("trust removal should cost more than membership removal: trust(%d,%d) member(%d,%d)", e1, d1, e2, d2)
	}
}
