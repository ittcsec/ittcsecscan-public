package pipeline

import (
	"sort"
	"strconv"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
	"github.com/ittcsec/ittcsecscan/internal/risk"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// RankedFinding is a finding with its computed risk and the transparent risk basis.
// Native is the entity's native id, kept for display (Finding.Entity is the stable id).
// Plan is the remediation plan for a failing finding (real guidance or an honest
// named gap); it is nil for non-failing findings, where remediation does not apply.
type RankedFinding struct {
	Finding   model.Finding
	Native    string
	Basis     []string
	Grounding rules.Grounding          // the evidence the finding was derived from (for the report)
	Trace     []string                 // the evaluation trace (for the report)
	Plan      *remediate.GeneratedPlan // remediation for a failing finding, else nil
}

// RankedPath is an attack path with its computed risk and the transparent basis.
type RankedPath struct {
	Path  model.AttackPath
	Risk  int
	Basis []string
}

// rankFindings scores each finding with the risk model and returns them ordered by
// risk descending. The risk inputs are assembled from the finding's rule severity and
// the affected entity's exposure, privilege, sensitivity, and criticality facts (the
// facts the analysis engines materialized onto the graph). It never alters an observed
// state or confidence: risk.ToFinding is the facts-unchanged mapping.
func rankFindings(g *normalize.NormalizedScan, findings []rules.Result, ruleset []rules.Rule) []RankedFinding {
	sev := make(map[string]model.Severity, len(ruleset))
	for _, r := range ruleset {
		sev[r.ID] = r.Severity
	}
	byNative := make(map[string]model.Entity, len(g.Entities))
	for _, e := range g.Entities {
		byNative[e.NativeID] = e
	}
	out := make([]RankedFinding, 0, len(findings))
	for _, r := range findings {
		e := byNative[r.EntityID]
		in := entityRiskInputs(r.State, sev[r.Rule.RuleID], r.Confidence, e)
		f, sc := risk.ToFinding(r.Rule, e.ID, in, r.Detail)
		rf := RankedFinding{Finding: f, Native: r.EntityID, Basis: sc.Basis, Grounding: r.Grounding, Trace: r.Trace}
		if r.State == model.Fail {
			plan := remediate.Plan(r.Rule, e)
			rf.Plan = &plan
		}
		out = append(out, rf)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Finding.Risk != out[j].Finding.Risk {
			return out[i].Finding.Risk > out[j].Finding.Risk
		}
		if out[i].Finding.Rule.RuleID != out[j].Finding.Rule.RuleID {
			return out[i].Finding.Rule.RuleID < out[j].Finding.Rule.RuleID
		}
		return out[i].Native < out[j].Native
	})
	return out
}

// rankPaths scores each attack path with the risk model and returns them ordered by
// risk descending. A path's severity comes from its target privilege, its confidence
// is the path confidence, its entry is internet-exposed by construction, and its impact
// from the target entity's facts.
func rankPaths(g *normalize.NormalizedScan, paths []model.AttackPath) []RankedPath {
	byID := make(map[model.StableID]model.Entity, len(g.Entities))
	for _, e := range g.Entities {
		byID[e.ID] = e
	}
	out := make([]RankedPath, 0, len(paths))
	for _, p := range paths {
		t := byID[p.Target]
		in := risk.Inputs{
			State:           model.Fail, // a path is an actionable exposure-to-privilege route
			Severity:        severityForPrivilege(p.Score),
			Confidence:      p.Confidence,
			InternetExposed: true, // the entry is internet-exposed by construction
			Sensitivity:     model.Sensitivity(attr(t, "sensitivity")),
			Privilege:       attr(t, "privilege_level"),
			Criticality:     atoiOr0(attr(t, "business_criticality")),
		}
		sc := risk.Compute(in)
		out = append(out, RankedPath{Path: p, Risk: sc.Value, Basis: sc.Basis})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		if out[i].Path.Entry != out[j].Path.Entry {
			return out[i].Path.Entry < out[j].Path.Entry
		}
		return out[i].Path.Target < out[j].Path.Target
	})
	return out
}

func entityRiskInputs(state model.Outcome, sev model.Severity, conf model.Confidence, e model.Entity) risk.Inputs {
	return risk.Inputs{
		State:           state,
		Severity:        sev,
		Confidence:      conf,
		InternetExposed: attr(e, "internet_exposed") == "true",
		AllPortsExposed: attr(e, "internet_exposed_all_ports") == "true",
		Sensitivity:     model.Sensitivity(attr(e, "sensitivity")),
		Privilege:       attr(e, "privilege_level"),
		Criticality:     atoiOr0(attr(e, "business_criticality")),
	}
}

func attr(e model.Entity, k string) string {
	if e.Attributes == nil {
		return ""
	}
	return e.Attributes[k]
}

func atoiOr0(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// severityForPrivilege maps an attack path's target privilege weight to a severity.
func severityForPrivilege(score int) model.Severity {
	switch {
	case score >= 100:
		return model.SeverityCritical
	case score >= 70:
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}
