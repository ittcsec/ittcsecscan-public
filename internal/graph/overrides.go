package graph

import (
	"strconv"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// ApplyOverrides applies audited business-criticality overrides onto the graph
// (ADR-0025 section 4). Overrides are given oldest first; for each entity the last
// one is the effective override. It sets model.Entity.Criticality and materializes
// the effective value and its provenance (actor, reason) as facts the detection
// engine can read. It is deterministic and clock-free: effective ordering is the
// input order (the store's append order), never a wall-clock read, so it is safe
// under the internal/graph determinism gate. It only adds facts, never removing the
// derived classification, which is a separate output: an override is a human input
// layered over the derived sensitivity, never an erasure of it.
func ApplyOverrides(g *normalize.NormalizedScan, overrides []model.CriticalityOverride) {
	if g == nil || len(overrides) == 0 {
		return
	}
	eff := make(map[model.StableID]model.CriticalityOverride, len(overrides))
	for _, ov := range overrides {
		eff[ov.Entity] = ov // last wins: input is oldest first
	}
	for i := range g.Entities {
		ov, ok := eff[g.Entities[i].ID]
		if !ok {
			continue
		}
		g.Entities[i].Criticality = ov.Criticality
		if g.Entities[i].Attributes == nil {
			g.Entities[i].Attributes = map[string]string{}
		}
		a := g.Entities[i].Attributes
		a["business_criticality"] = strconv.Itoa(ov.Criticality)
		a["criticality_override_actor"] = ov.Actor
		if ov.Reason != "" {
			a["criticality_override_reason"] = ov.Reason
		}
	}
}
