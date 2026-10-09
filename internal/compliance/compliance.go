// Package compliance is ITTCsecProof (ADR-0034): a declarative mapping layer, keyed by
// rule id, that attributes real findings to the controls of common regulatory and audit
// frameworks (NIS2, ISO 27001, GDPR, SOC 2, DORA, CRA), and a pure function that reports
// per-control status derived ONLY from findings.
//
// It never emits a compliance verdict for a control with no backing finding, and never a
// certification: "not assessed" is the honest default. The mapping is content, not logic
// (it introduces no new provider semantics and no new finding); this package only reads it
// and reconciles it against the findings the detection engine already produced.
package compliance

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Status is a per-control evidence status, worst first. "not assessed" is never rendered
// as "compliant": it means no finding backs the control, or its evidence is incomplete.
type Status string

const (
	// StatusFail: a rule mapped to the control produced a failing finding (real evidence
	// the control is not met).
	StatusFail Status = "fail"
	// StatusPass: every mapped rule that produced a conclusive finding passed, and none was
	// unknown or errored (evidence the control is met, for exactly what was assessed).
	StatusPass Status = "pass"
	// StatusNotAssessed: no finding backs the control. No rule maps to it, or the mapped
	// rules returned only unknown/error/not-applicable, or part of the evidence was
	// unknown or errored (incomplete coverage is never read as met).
	StatusNotAssessed Status = "not_assessed"
)

// Control is a single framework control reference. It is an identifier only; the
// framework's control-catalog text is never reproduced (ADR-0034, copyright).
type Control struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
}

// FrameworkMeta records a framework's version and effective date (the design).
type FrameworkMeta struct {
	Framework     string `json:"framework"`
	Version       string `json:"version"`
	EffectiveDate string `json:"effective_date"`
}

// ruleMapping is one rule id's control references across frameworks.
type ruleMapping struct {
	RuleID   string    `json:"rule_id"`
	Controls []Control `json:"controls"`
}

// Mapping is the declarative, versioned mapping content.
type Mapping struct {
	SchemaVersion int             `json:"schema_version"`
	Frameworks    []FrameworkMeta `json:"frameworks"`
	Rules         []ruleMapping   `json:"rules"`
}

// Finding is the minimal finding view the status computation needs: a rule id and its
// outcome. The caller adapts the engine's richer findings onto this.
type Finding struct {
	RuleID string
	State  model.Outcome
}

// ControlResult is one control's evidence status and the mapped rule ids that produced a
// conclusive finding contributing to it (the backing evidence, for the explanation).
type ControlResult struct {
	Control string
	Status  Status
	Rules   []string
}

// FrameworkResult is one framework's coverage: its metadata, the per-control results for
// the controls the mapping references, and the counts that lead the view.
type FrameworkResult struct {
	Framework     string
	Version       string
	EffectiveDate string
	Controls      []ControlResult
	Failed        int
	Passed        int
	NotAssessed   int
}

// Result is the ITTCsecProof view: one entry per mapped framework.
type Result struct {
	Frameworks []FrameworkResult
}

// Load parses and validates the mapping content.
func Load(b []byte) (Mapping, error) {
	var m Mapping
	if err := json.Unmarshal(b, &m); err != nil {
		return Mapping{}, fmt.Errorf("compliance: parse mapping: %w", err)
	}
	if err := m.Validate(); err != nil {
		return Mapping{}, err
	}
	return m, nil
}

// Validate checks the mapping is internally consistent: a known schema version, a
// non-empty framework set with unique names, and rules whose controls reference only
// declared frameworks, with no duplicate rule ids. It does not check that rule ids exist
// in a ruleset; that reconciliation is a separate step (ValidateAgainstRules) so a drift
// between the mapping and the shipped rules is caught as its own explicit error.
func (m Mapping) Validate() error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("compliance: unsupported schema_version %d", m.SchemaVersion)
	}
	if len(m.Frameworks) == 0 {
		return fmt.Errorf("compliance: no frameworks declared")
	}
	known := map[string]bool{}
	for _, f := range m.Frameworks {
		if f.Framework == "" {
			return fmt.Errorf("compliance: a framework has an empty name")
		}
		if known[f.Framework] {
			return fmt.Errorf("compliance: duplicate framework %q", f.Framework)
		}
		if f.Version == "" || f.EffectiveDate == "" {
			return fmt.Errorf("compliance: framework %q missing version or effective_date", f.Framework)
		}
		known[f.Framework] = true
	}
	seen := map[string]bool{}
	for _, r := range m.Rules {
		if r.RuleID == "" {
			return fmt.Errorf("compliance: a rule mapping has an empty rule_id")
		}
		if seen[r.RuleID] {
			return fmt.Errorf("compliance: duplicate rule mapping %q", r.RuleID)
		}
		seen[r.RuleID] = true
		if len(r.Controls) == 0 {
			return fmt.Errorf("compliance: rule %q maps to no controls", r.RuleID)
		}
		for _, c := range r.Controls {
			if c.Control == "" {
				return fmt.Errorf("compliance: rule %q has a control with an empty id", r.RuleID)
			}
			if !known[c.Framework] {
				return fmt.Errorf("compliance: rule %q references undeclared framework %q", r.RuleID, c.Framework)
			}
		}
	}
	return nil
}

// ValidateAgainstRules reports any mapped rule id that is not in the provided set of known
// rule ids, so the mapping cannot silently drift from the shipped detection rules.
func (m Mapping) ValidateAgainstRules(known map[string]bool) error {
	var missing []string
	for _, r := range m.Rules {
		if !known[r.RuleID] {
			missing = append(missing, r.RuleID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("compliance: mapping references unknown rule ids: %v", missing)
	}
	return nil
}

// Evaluate computes the per-control evidence status for every framework, from the mapping
// and the findings alone. Status comes only from findings:
//
//   - fail  when any rule mapped to the control produced a failing finding;
//   - pass  when at least one mapped rule produced a passing finding and none produced a
//     fail, unknown, or error (so a control is "met" only when all its evidence is met);
//   - not assessed  otherwise: no finding backs it, or part of its evidence was unknown,
//     errored, or only not-applicable.
//
// not-applicable findings are treated as no evidence (neither pass nor fail): a rule that
// does not apply to what was scanned contributes nothing to a control's status. The result
// is fully deterministic: frameworks keep the mapping's order, controls are sorted, and
// each control's backing rule ids are sorted.
func Evaluate(m Mapping, findings []Finding) Result {
	// states[ruleID] = the set of outcomes seen for that rule across entities.
	states := map[string][]model.Outcome{}
	for _, f := range findings {
		states[f.RuleID] = append(states[f.RuleID], f.State)
	}

	// For each framework, collect the controls the mapping references and the rule ids
	// that map to each.
	type key struct{ framework, control string }
	controlRules := map[key][]string{}
	for _, r := range m.Rules {
		for _, c := range r.Controls {
			k := key{c.Framework, c.Control}
			controlRules[k] = append(controlRules[k], r.RuleID)
		}
	}

	var res Result
	for _, fm := range m.Frameworks {
		fr := FrameworkResult{Framework: fm.Framework, Version: fm.Version, EffectiveDate: fm.EffectiveDate}
		// The controls this framework's mapping references, sorted and de-duplicated.
		var controls []string
		for k := range controlRules {
			if k.framework == fm.Framework {
				controls = append(controls, k.control)
			}
		}
		sort.Strings(controls)
		for _, ctrl := range controls {
			ruleIDs := uniqueSorted(controlRules[key{fm.Framework, ctrl}])
			status, backing := controlStatus(ruleIDs, states)
			fr.Controls = append(fr.Controls, ControlResult{Control: ctrl, Status: status, Rules: backing})
			switch status {
			case StatusFail:
				fr.Failed++
			case StatusPass:
				fr.Passed++
			default:
				fr.NotAssessed++
			}
		}
		res.Frameworks = append(res.Frameworks, fr)
	}
	return res
}

// controlStatus derives one control's status from the outcomes of its mapped rules, and
// returns the rule ids that produced a conclusive (pass or fail) finding as the backing
// evidence. The precedence is fail, then not-assessed on any unknown/error, then pass.
func controlStatus(ruleIDs []string, states map[string][]model.Outcome) (Status, []string) {
	var anyFail, anyPass, anyUnknown bool
	var backing []string
	for _, id := range ruleIDs {
		for _, st := range states[id] {
			switch st {
			case model.Fail:
				anyFail = true
				backing = append(backing, id)
			case model.Pass:
				anyPass = true
				backing = append(backing, id)
			case model.OutcomeUnknown, model.OutcomeError:
				anyUnknown = true
			case model.NotApplicable:
				// no evidence; contributes nothing
			}
		}
	}
	backing = uniqueSorted(backing)
	switch {
	case anyFail:
		return StatusFail, backing
	case anyUnknown:
		// Incomplete evidence is never read as met, even if some mapped rule passed.
		return StatusNotAssessed, backing
	case anyPass:
		return StatusPass, backing
	default:
		return StatusNotAssessed, backing
	}
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
