package remediate

import "github.com/ittcsec/ittcsecscan/internal/model"

// GeneratedPlan is the remediation artifact for one finding: the canonical,
// schema-governed plan content plus two unkeyed content-integrity hashes that
// belong to the artifact rather than the model document (mirroring how
// report.Report carries its content hash). CurrentStateHash fingerprints the
// entity's state at plan time and is what drift detection compares against
// immediately before any apply. PlanHash is the content hash of the plan itself,
// the value an approval binds to.
type GeneratedPlan struct {
	model.RemediationPlan
	CurrentStateHash string `json:"current_state_hash"`
	PlanHash         string `json:"plan_hash"`
}

// Plan produces the immutable, plan-only remediation for one finding against the
// entity it fired on. Content is parameterized only by the entity's real
// identifiers and collected facts. When no verified template exists the plan is
// an honest named gap: Available is false and GapReason states why, never a
// fabricated action.
func Plan(finding model.RuleRef, e model.Entity) GeneratedPlan {
	p := model.RemediationPlan{
		SchemaVersion: model.SchemaVersion,
		Finding:       finding,
		Entity:        e.ID,
		Reversible:    false,
	}
	if build, ok := templates[finding.RuleID]; ok {
		c := build(e)
		p.Available = true
		p.Actions = c.Actions
		p.Preconditions = c.Preconditions
		p.RequiredPrivilege = c.RequiredPriv
		p.SideEffects = c.SideEffects
		p.Verification = c.Verification
		p.Reversible = c.Reversible
		p.Rollback = c.Rollback
	} else {
		p.Available = false
		if reason, ok := namedGaps[finding.RuleID]; ok {
			p.GapReason = reason
		} else {
			p.GapReason = "No verified remediation template exists for this rule yet. Guidance is a tracked gap; no fabricated action is shown."
		}
	}
	return GeneratedPlan{
		RemediationPlan:  p,
		CurrentStateHash: CurrentStateHash(e),
		PlanHash:         planHash(p),
	}
}
