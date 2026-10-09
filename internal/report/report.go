// Package report renders JSON, SARIF, HTML, PDF, and DOCX from one immutable report
// model (ADR-0028). The model is built once from the analysis outputs, frozen, and
// content-hashed; every format is a pure renderer over it, so the formats cannot
// diverge. Coverage and blind spots precede findings. Every customer-facing string is
// redacted and stripped of forbidden dashes before it enters the model, and no
// renderer emits guidance-shaped placeholder text for remediation that does not exist.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/compliance"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
)

// schemaVersion is the report model's version (schemas/model/v1/report.schema.json).
const schemaVersion = 1

// Input is the raw material a report is built from: the analysis outputs plus the scan
// context. Timestamps arrive pre-formatted (the report engine holds no clock).
type Input struct {
	Tenant          string
	ToolVersion     string
	Started         string // RFC 3339, formatted by the caller
	Completed       string
	Providers       []ProviderCoverage
	Findings        []pipeline.RankedFinding
	Paths           []pipeline.RankedPath
	Cuts            []model.CutSet
	Classifications []model.Classification
	// Identity carries the effective-privilege resolution (deny-override semantics,
	// ADR-0022) for the ITTCsecID section. Grants, and whether the resolution was
	// complete, come straight from the engine; nothing is re-derived here.
	IdentityGrants   []model.Permission
	IdentityComplete bool
	IdentityGaps     []string
	// Change inputs carry the later-scan change-detection result for the scan being
	// reported (ADR-0011 section 1). Strings are raw here; Build sanitizes them.
	ChangeScanID  int64
	EntityChanges []EntityChange
	EdgeChanges   []EdgeChange
	// ComplianceMapping is the ITTCsecProof mapping content (ADR-0034). Build reconciles
	// it against Findings to produce the compliance section; an empty mapping yields an
	// empty section (no frameworks), never a fabricated one.
	ComplianceMapping compliance.Mapping
}

// ProviderCoverage is one provider's authentication result and completeness records.
type ProviderCoverage struct {
	Provider      string
	Account       string
	Authenticated bool
	AuthError     string
	Records       []collect.Completeness
}

// Report is the immutable, content-hashed report model. Every string in it is already
// sanitized (redacted, no forbidden dashes). It is built once and never mutated.
type Report struct {
	SchemaVersion   int              `json:"schema_version"`
	Tenant          string           `json:"tenant"`
	ToolVersion     string           `json:"tool_version"`
	Started         string           `json:"started,omitempty"`
	Completed       string           `json:"completed,omitempty"`
	Coverage        Coverage         `json:"coverage"`
	Findings        []Finding        `json:"findings"`
	Paths           []Path           `json:"paths"`
	Cuts            []Cut            `json:"cuts"`
	Classifications []Classification `json:"classifications"`
	// Identity is the ITTCsecID section: who effectively holds what privilege, with
	// deny-override semantics, plus the honest dormant-privilege gap.
	Identity IdentitySection `json:"identity"`
	// Changes is the diff section: what the change-detection engine recorded as
	// appeared, changed, or disappeared in this scan relative to the prior state.
	Changes ChangeSection `json:"changes"`
	// Compliance is the ITTCsecProof section: per-control evidence status for each mapped
	// framework, derived only from findings. It is an evidence-coverage map, never a
	// certification; "not assessed" is the honest default.
	Compliance ComplianceSection `json:"compliance"`
	// Remediation is the honest, tenant-wide statement that actionable remediation is
	// not yet produced; it is a named gap, never placeholder guidance (RP-1).
	Remediation string `json:"remediation"`
	// Hash is the SHA-256 of the report with this field empty: the immutability receipt
	// linking the rendered formats to one frozen model.
	Hash string `json:"hash"`
}

// Coverage is the coverage and blind-spot statement, which precedes findings.
type Coverage struct {
	Complete  bool          `json:"complete"`
	Providers []ProviderCov `json:"providers"`
	Gaps      []string      `json:"gaps"`
}

type ProviderCov struct {
	Provider      string      `json:"provider"`
	Account       string      `json:"account,omitempty"`
	Authenticated bool        `json:"authenticated"`
	AuthError     string      `json:"auth_error,omitempty"`
	Records       []CovRecord `json:"records"`
}

type CovRecord struct {
	Service   string `json:"service"`
	Region    string `json:"region"`
	Status    string `json:"status"`
	Collected int    `json:"collected"`
	Reason    string `json:"reason,omitempty"`
}

// DormantGapStatus is the honest named gap for dormant-privilege detection: it is not
// built, because no last-used or credential-age signal is collected (deferred,
// ADR-0021 section 7). It is reported as an explicit gap, never inferred from a weaker
// proxy (the never-guess rule, ADR-0004).
const DormantGapStatus = "dormant-privilege detection not available: no last-used or credential-age signal is collected (deferred, ADR-0021 section 7); it is reported as a gap, not inferred"

// IdentitySection is the ITTCsecID view: effective-privilege grants with deny-override
// semantics, the resolution's completeness, and the dormant-privilege gap. Every string
// is sanitized.
type IdentitySection struct {
	Grants        []AccessGrant `json:"grants"`
	Complete      bool          `json:"complete"`
	Gaps          []string      `json:"gaps"`
	DormantStatus string        `json:"dormant_status"`
}

// ChangeSection is the diff view: the entities and edges the change-detection engine
// recorded for this scan, relative to the prior state. An empty section with a scan id is
// honest for a baseline (first) scan: there is no prior state to compare.
type ChangeSection struct {
	ScanID   int64          `json:"scan_id"`
	Entities []EntityChange `json:"entities"`
	Edges    []EdgeChange   `json:"edges"`
}

// EntityChange is one entity that appeared, changed, or disappeared. Entity is the native
// id; both it and Name are sanitized.
type EntityChange struct {
	Change string `json:"change"`
	Type   string `json:"type"`
	Entity string `json:"entity"`
	Name   string `json:"name,omitempty"`
}

// EdgeChange is one edge that appeared, changed, or disappeared, with sanitized endpoints.
type EdgeChange struct {
	Change string `json:"change"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Target string `json:"target"`
}

// ComplianceSection is the ITTCsecProof view (ADR-0034): per-framework coverage over the
// controls the mapping references, with status derived only from findings. It never states
// or implies a tenant "is compliant"; it states what the collected evidence does and does
// not show. Every string is sanitized.
type ComplianceSection struct {
	Frameworks []FrameworkCompliance `json:"frameworks"`
}

// FrameworkCompliance is one framework's evidence coverage. The counts lead the view:
// of the controls this mapping references for the framework, how many have failing
// evidence, how many have passing evidence, and how many are not assessed (which for the
// current rule set is the large majority). Version and EffectiveDate pin the mapped
// framework edition (the design).
type FrameworkCompliance struct {
	Framework     string              `json:"framework"`
	Version       string              `json:"version"`
	EffectiveDate string              `json:"effective_date"`
	Failed        int                 `json:"failed"`
	Passed        int                 `json:"passed"`
	NotAssessed   int                 `json:"not_assessed"`
	Controls      []ControlCompliance `json:"controls"`
}

// ControlCompliance is one control's evidence status and the rule ids that produced a
// conclusive finding backing it. Status is "fail", "pass", or "not_assessed"; it is never
// "compliant".
type ControlCompliance struct {
	Control string   `json:"control"`
	Status  string   `json:"status"`
	Rules   []string `json:"rules,omitempty"`
}

// AccessGrant is one principal's effective privilege. Effect is "allow" when the
// privilege survives or "deny" when a permission-boundary cap or an explicit deny
// removed it (deny overrides allow, ADR-0022). Via records how it was reached
// (inherited-from and any conditions), for the explanation trace.
type AccessGrant struct {
	Principal string   `json:"principal"`
	Privilege string   `json:"privilege"`
	Effect    string   `json:"effect"`
	Via       []string `json:"via,omitempty"`
}

// Finding is one report finding: risk, confidence, evidence, and per-finding
// remediation (real guidance for a failing finding with a verified template, or an
// honest named gap). Every string is sanitized.
type Finding struct {
	Rule        string      `json:"rule"`
	Entity      string      `json:"entity"`
	EntityName  string      `json:"entity_name,omitempty"`
	State       string      `json:"state"`
	Risk        int         `json:"risk"`
	Confidence  int         `json:"confidence"`
	RiskBasis   []string    `json:"risk_basis"`
	Evidence    Evidence    `json:"evidence"`
	Trace       []string    `json:"trace,omitempty"`
	Detail      string      `json:"detail,omitempty"`
	Remediation Remediation `json:"remediation"`
}

// Remediation is a report finding's remediation view. When Available is false the
// finding type has no verified remediation yet and Statement is the honest named
// gap (never placeholder guidance). When Available is true the actions carry
// doc-verified portal, CLI, and IaC steps, and the plan hash lets an operator bind
// an approval to this exact plan.
type Remediation struct {
	Available     bool        `json:"available"`
	Statement     string      `json:"statement"`
	Actions       []RemAction `json:"actions,omitempty"`
	Preconditions []string    `json:"preconditions,omitempty"`
	Privilege     []string    `json:"required_privilege,omitempty"`
	SideEffects   []string    `json:"side_effects,omitempty"`
	Verification  []string    `json:"verification,omitempty"`
	Reversible    bool        `json:"reversible"`
	Rollback      []string    `json:"rollback,omitempty"`
	PlanHash      string      `json:"plan_hash,omitempty"`
}

// RemAction is one corrective step: three renderings (portal, CLI, IaC) of the same
// change, with the privilege it needs.
type RemAction struct {
	Provider    string   `json:"provider"`
	Service     string   `json:"service"`
	Summary     string   `json:"summary"`
	PortalSteps []string `json:"portal_steps,omitempty"`
	CLI         []string `json:"cli,omitempty"`
	IaC         string   `json:"iac,omitempty"`
	Privilege   []string `json:"privilege,omitempty"`
}

// buildRemediation renders a finding's remediation view from its generated plan,
// sanitizing every customer-facing string before it enters the frozen model. A
// failing finding carries a plan (real guidance, or an honest named gap when the
// finding type has no verified template). A non-failing finding carries no plan,
// and the statement says why no remediation is proposed rather than showing
// guidance-shaped text.
func buildRemediation(rf pipeline.RankedFinding) Remediation {
	if rf.Plan == nil {
		if rf.Finding.State == model.Pass {
			return Remediation{Statement: sanitize("No remediation is needed; the check passes.")}
		}
		return Remediation{Statement: sanitize("No remediation is proposed: the result is unknown, so the coverage gap must be closed before a plan can be generated.")}
	}
	p := rf.Plan
	if !p.Available {
		return Remediation{Statement: sanitize(p.GapReason)}
	}
	rem := Remediation{
		Available:     true,
		Preconditions: sanitizeAll(p.Preconditions),
		Privilege:     sanitizeAll(p.RequiredPrivilege),
		SideEffects:   sanitizeAll(p.SideEffects),
		Verification:  sanitizeAll(p.Verification),
		Reversible:    p.Reversible,
		Rollback:      sanitizeAll(p.Rollback),
		PlanHash:      sanitize(p.PlanHash),
	}
	if len(p.Actions) > 0 {
		rem.Statement = sanitize(p.Actions[0].Summary)
	}
	for _, a := range p.Actions {
		rem.Actions = append(rem.Actions, RemAction{
			Provider:    sanitize(string(a.Provider)),
			Service:     sanitize(a.Service),
			Summary:     sanitize(a.Summary),
			PortalSteps: sanitizeAll(a.PortalSteps),
			CLI:         sanitizeAll(a.CLI),
			IaC:         sanitize(a.IaC),
			Privilege:   sanitizeAll(a.Privilege),
		})
	}
	return rem
}

type Evidence struct {
	Nodes []string `json:"nodes,omitempty"`
	Edges []string `json:"edges,omitempty"`
	Facts []string `json:"facts,omitempty"`
}

type Path struct {
	Entry      string   `json:"entry"`
	Target     string   `json:"target"`
	Risk       int      `json:"risk"`
	Score      int      `json:"score"`
	Confidence int      `json:"confidence"`
	RiskBasis  []string `json:"risk_basis"`
	Steps      []Step   `json:"steps"`
}

type Step struct {
	Node      string `json:"node"`
	Via       string `json:"via,omitempty"`
	Technique string `json:"technique,omitempty"`
}

type Cut struct {
	Kind          string `json:"kind"`
	Source        string `json:"source"`
	Target        string `json:"target"`
	Description   string `json:"description"`
	PathsRemoved  int    `json:"paths_removed"`
	RiskReduction int    `json:"risk_reduction"`
	Effort        int    `json:"effort"`
	Disruption    int    `json:"disruption"`
}

type Classification struct {
	Entity      string `json:"entity"`
	Sensitivity string `json:"sensitivity"`
	Confidence  int    `json:"confidence"`
	Method      string `json:"method"`
}

// Build assembles the immutable report model from the analysis outputs. Every
// customer-facing string is sanitized as it enters the model; findings and paths keep
// their risk order; coverage is computed from the real completeness records; and the
// content hash is set last. The result is frozen: renderers read it, never change it.
func Build(in Input) Report {
	r := Report{
		SchemaVersion:   schemaVersion,
		Tenant:          in.Tenant,
		ToolVersion:     sanitize(in.ToolVersion),
		Started:         sanitize(in.Started),
		Completed:       sanitize(in.Completed),
		Coverage:        buildCoverage(in.Providers),
		Remediation:     RemediationStatus,
		Findings:        []Finding{},
		Paths:           []Path{},
		Cuts:            []Cut{},
		Classifications: []Classification{},
	}
	for _, rf := range in.Findings {
		if rf.Finding.State == model.NotApplicable {
			continue // not a finding about the tenant; counted in coverage-driven totals elsewhere
		}
		r.Findings = append(r.Findings, Finding{
			Rule:       sanitize(rf.Finding.Rule.RuleID),
			Entity:     sanitize(rf.Native),
			EntityName: sanitize(rf.Native),
			State:      string(rf.Finding.State),
			Risk:       rf.Finding.Risk,
			Confidence: int(rf.Finding.Confidence),
			RiskBasis:  sanitizeAll(rf.Basis),
			Evidence: Evidence{
				Nodes: sanitizeAll(rf.Grounding.Nodes),
				Edges: sanitizeAll(rf.Grounding.Edges),
				Facts: sanitizeAll(rf.Grounding.Facts),
			},
			Trace:       sanitizeAll(rf.Trace),
			Detail:      sanitize(rf.Finding.Detail),
			Remediation: buildRemediation(rf),
		})
	}
	for _, rp := range in.Paths {
		p := Path{
			Entry: sanitize(string(rp.Path.Entry)), Target: sanitize(string(rp.Path.Target)),
			Risk: rp.Risk, Score: rp.Path.Score, Confidence: int(rp.Path.Confidence),
			RiskBasis: sanitizeAll(rp.Basis), Steps: []Step{},
		}
		for _, s := range rp.Path.Steps {
			p.Steps = append(p.Steps, Step{Node: sanitize(string(s.Node)), Via: sanitize(string(s.Via)), Technique: sanitize(s.Technique)})
		}
		r.Paths = append(r.Paths, p)
	}
	for _, c := range in.Cuts {
		if len(c.Changes) == 0 {
			continue
		}
		ch := c.Changes[0]
		r.Cuts = append(r.Cuts, Cut{
			Kind: sanitize(string(ch.Kind)), Source: sanitize(string(ch.Source)), Target: sanitize(string(ch.Target)),
			Description:  sanitize(ch.Description),
			PathsRemoved: c.PathsRemoved, RiskReduction: c.RiskReduction, Effort: c.Effort, Disruption: c.Disruption,
		})
	}
	classes := append([]model.Classification(nil), in.Classifications...)
	sort.SliceStable(classes, func(i, j int) bool { return classes[i].Entity < classes[j].Entity })
	for _, c := range classes {
		r.Classifications = append(r.Classifications, Classification{
			Entity: sanitize(string(c.Entity)), Sensitivity: sanitize(c.Label),
			Confidence: int(c.Confidence), Method: sanitize(c.Method),
		})
	}
	grants := append([]model.Permission(nil), in.IdentityGrants...)
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Principal != grants[j].Principal {
			return grants[i].Principal < grants[j].Principal
		}
		return grants[i].Action < grants[j].Action
	})
	r.Identity = IdentitySection{
		Grants:        []AccessGrant{},
		Complete:      in.IdentityComplete,
		Gaps:          sanitizeAll(in.IdentityGaps),
		DormantStatus: DormantGapStatus,
	}
	for _, gr := range grants {
		var via []string
		if gr.InheritedFrom != "" {
			via = append(via, sanitize("inherited from "+string(gr.InheritedFrom)))
		}
		for _, c := range gr.Condition {
			via = append(via, sanitize(c.Key+" "+c.Operator+" "+strings.Join(c.Values, ",")))
		}
		r.Identity.Grants = append(r.Identity.Grants, AccessGrant{
			Principal: sanitize(string(gr.Principal)),
			Privilege: sanitize(gr.Action),
			Effect:    sanitize(string(gr.Effect)),
			Via:       via,
		})
	}
	r.Changes = ChangeSection{ScanID: in.ChangeScanID, Entities: []EntityChange{}, Edges: []EdgeChange{}}
	for _, ec := range in.EntityChanges {
		r.Changes.Entities = append(r.Changes.Entities, EntityChange{
			Change: sanitize(ec.Change), Type: sanitize(ec.Type),
			Entity: sanitize(ec.Entity), Name: sanitize(ec.Name),
		})
	}
	for _, ec := range in.EdgeChanges {
		r.Changes.Edges = append(r.Changes.Edges, EdgeChange{
			Change: sanitize(ec.Change), Kind: sanitize(ec.Kind),
			Source: sanitize(ec.Source), Target: sanitize(ec.Target),
		})
	}
	r.Compliance = buildCompliance(in.ComplianceMapping, in.Findings)
	r.Hash = contentHash(r)
	return r
}

// buildCompliance reconciles the mapping against the findings (ITTCsecProof, ADR-0034) and
// sanitizes the result into the frozen model. Status comes only from findings; a control
// with no backing finding is "not assessed". An empty mapping yields an empty section.
func buildCompliance(m compliance.Mapping, findings []pipeline.RankedFinding) ComplianceSection {
	cf := make([]compliance.Finding, 0, len(findings))
	for _, rf := range findings {
		cf = append(cf, compliance.Finding{RuleID: rf.Finding.Rule.RuleID, State: rf.Finding.State})
	}
	res := compliance.Evaluate(m, cf)
	out := ComplianceSection{Frameworks: []FrameworkCompliance{}}
	for _, fr := range res.Frameworks {
		fc := FrameworkCompliance{
			Framework:     sanitize(fr.Framework),
			Version:       sanitize(fr.Version),
			EffectiveDate: sanitize(fr.EffectiveDate),
			Failed:        fr.Failed,
			Passed:        fr.Passed,
			NotAssessed:   fr.NotAssessed,
			Controls:      []ControlCompliance{},
		}
		for _, c := range fr.Controls {
			fc.Controls = append(fc.Controls, ControlCompliance{
				Control: sanitize(c.Control),
				Status:  string(c.Status),
				Rules:   sanitizeAll(c.Rules),
			})
		}
		out.Frameworks = append(out.Frameworks, fc)
	}
	return out
}

func buildCoverage(providers []ProviderCoverage) Coverage {
	cov := Coverage{Complete: true, Providers: []ProviderCov{}, Gaps: []string{}}
	gapSet := map[string]bool{}
	if len(providers) == 0 {
		cov.Complete = false // nothing scanned is not "complete coverage"
	}
	for _, p := range providers {
		pc := ProviderCov{Provider: sanitize(p.Provider), Account: sanitize(p.Account), Authenticated: p.Authenticated, AuthError: sanitize(p.AuthError), Records: []CovRecord{}}
		if !p.Authenticated {
			cov.Complete = false
			gapSet[sanitize(p.Provider)+":not-authenticated"] = true
		}
		if len(p.Records) == 0 && p.Authenticated {
			cov.Complete = false
		}
		for _, rec := range p.Records {
			pc.Records = append(pc.Records, CovRecord{
				Service: sanitize(rec.Service), Region: sanitize(rec.Region),
				Status: string(rec.Status), Collected: rec.Collected, Reason: sanitize(rec.Reason),
			})
			if rec.Status != collect.Complete {
				cov.Complete = false
				gapSet[sanitize(rec.Service)+":"+string(rec.Status)] = true
			}
		}
		cov.Providers = append(cov.Providers, pc)
	}
	for g := range gapSet {
		cov.Gaps = append(cov.Gaps, g)
	}
	sort.Strings(cov.Gaps)
	return cov
}

// contentHash is the SHA-256 of the report with the Hash field empty, hex-encoded.
func contentHash(r Report) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
