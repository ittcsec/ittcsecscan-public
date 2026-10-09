package graph

import (
	"fmt"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Cuts computes minimum-cut remediation candidates from the attack paths (ADR-0026
// section 4). Each candidate is one edge whose removal severs the paths that traverse
// it; candidates are ranked by risk reduction against a deterministic effort and
// disruption model, never by raw path count. It is pure and deterministic.
//
// Ranking is the "leverage" of a change: the weighted risk it removes per unit of
// effort plus disruption, so a low-effort change that severs a high-value path
// outranks a high-effort change that severs many low-value ones. The design
// requires effort weighed against risk reduction, not mathematical cost alone.
func Cuts(paths []model.AttackPath) []model.CutSet {
	type edgeKey struct {
		src, dst model.StableID
		kind     model.EdgeKind
	}
	severed := map[edgeKey][]model.AttackPath{}
	order := []edgeKey{}
	for _, p := range paths {
		for i := 1; i < len(p.Steps); i++ {
			k := edgeKey{p.Steps[i-1].Node, p.Steps[i].Node, p.Steps[i].Via}
			if _, seen := severed[k]; !seen {
				order = append(order, k)
			}
			severed[k] = append(severed[k], p)
		}
	}

	cuts := make([]model.CutSet, 0, len(order))
	for _, k := range order {
		ps := severed[k]
		risk := 0
		for _, p := range ps {
			// Weighted risk removed: the target's value discounted by how sure we are
			// the path exists. Never more than the paths actually severed.
			risk += p.Score * int(p.Confidence) / 100
		}
		eff, disr := changeCost(k.kind)
		cuts = append(cuts, model.CutSet{
			SchemaVersion: model.SchemaVersion,
			Changes:       []model.CutChange{{Source: k.src, Target: k.dst, Kind: k.kind, Description: cutDescription(k.kind)}},
			PathsRemoved:  len(ps),
			RiskReduction: risk,
			Effort:        eff,
			Disruption:    disr,
		})
	}

	sort.SliceStable(cuts, func(i, j int) bool {
		li, lj := leverage(cuts[i]), leverage(cuts[j])
		if li != lj {
			return li > lj // more risk removed per unit of effort+disruption first
		}
		if cuts[i].RiskReduction != cuts[j].RiskReduction {
			return cuts[i].RiskReduction > cuts[j].RiskReduction
		}
		ci, cj := cuts[i].Changes[0], cuts[j].Changes[0]
		if ci.Source != cj.Source {
			return ci.Source < cj.Source
		}
		return ci.Target < cj.Target
	})
	return cuts
}

// leverage is the ranking score: weighted risk removed per unit of effort plus
// disruption, scaled to keep integer resolution. Higher is a better remediation
// value. It weighs effort against risk reduction, never risk (or path count) alone.
func leverage(c model.CutSet) int {
	cost := c.Effort + c.Disruption
	if cost <= 0 {
		cost = 1
	}
	return c.RiskReduction * 100 / cost
}

// changeCost is the deterministic effort/disruption model per change type (ADR-0026
// section 4, AP-4): a documented first heuristic, not a claim of true remediation
// cost. Revoking a broad trust or federation is higher-touch and more disruptive than
// removing a single role assumption or group membership.
func changeCost(kind model.EdgeKind) (effort, disruption int) {
	switch kind {
	case model.EdgeMemberOf:
		return 2, 3
	case model.EdgeAssumes:
		return 3, 4
	case model.EdgeTrusts:
		return 5, 6
	case model.EdgeFederatesWith:
		return 6, 7
	}
	return 4, 4
}

func cutDescription(kind model.EdgeKind) string {
	switch kind {
	case model.EdgeMemberOf:
		return "remove the group membership that carries this reachability"
	case model.EdgeAssumes:
		return "revoke the role assumption on this path"
	case model.EdgeTrusts:
		return "remove the trust relationship on this path"
	case model.EdgeFederatesWith:
		return "remove the federation on this path"
	}
	return fmt.Sprintf("remove the %s edge on this path", kind)
}
