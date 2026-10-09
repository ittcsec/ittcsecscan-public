package model

// RemediationAction is one concrete corrective step for a finding, carrying the
// guidance a person (or, behind the experimental build tag, the executor) needs
// to make the change. All guidance is authored from official provider
// documentation and carried in code, so plan content is deterministic and
// offline: nothing is fetched or generated at runtime. Portal steps, the CLI
// command, and the IaC snippet are three renderings of the same single change.
type RemediationAction struct {
	Provider    Provider `json:"provider"`
	Service     string   `json:"service"`
	Summary     string   `json:"summary"`
	PortalSteps []string `json:"portal_steps,omitempty"`
	CLI         []string `json:"cli,omitempty"`
	IaC         string   `json:"iac,omitempty"`
	Privilege   []string `json:"privilege,omitempty"`
}

// RemediationPlan is the immutable, plan-only remediation content for exactly
// one finding. It is generated read-only. A safety invariant: nothing is
// ever executed without an immutable plan (current-state hash, actions,
// preconditions, privilege, side effects, verification, rollback) and an
// approval bound to the exact plan hash. The current-state hash and the plan's
// own content hash are unkeyed content integrity values carried on the generated
// artifact (remediate.GeneratedPlan), not on this canonical document, exactly as
// the report engine carries its content hash on report.Report rather than a
// model document (ADR-0014 section 4: keyed and store-side hashes never enter the
// model).
//
// When Available is false, the finding type has no apply-ready action today and
// GapReason states why, honestly, rather than a fabricated action. Reversible
// records whether the change can be undone; when it is false (for example Azure
// Key Vault purge protection, which cannot be disabled once enabled) Rollback
// says so plainly instead of promising a reversal that does not exist.
type RemediationPlan struct {
	SchemaVersion     int                 `json:"schema_version"`
	Finding           RuleRef             `json:"finding"`
	Entity            StableID            `json:"entity"`
	Available         bool                `json:"available"`
	GapReason         string              `json:"gap_reason,omitempty"`
	Actions           []RemediationAction `json:"actions,omitempty"`
	Preconditions     []string            `json:"preconditions,omitempty"`
	RequiredPrivilege []string            `json:"required_privilege,omitempty"`
	SideEffects       []string            `json:"side_effects,omitempty"`
	Approvals         []string            `json:"approvals,omitempty"`
	Verification      []string            `json:"verification,omitempty"`
	Reversible        bool                `json:"reversible"`
	Rollback          []string            `json:"rollback,omitempty"`
}
