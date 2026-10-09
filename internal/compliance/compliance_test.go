package compliance

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/packs"
)

// testMapping is a small, self-contained mapping exercising every status path.
func testMapping() Mapping {
	fw := func(n string) Control { return Control{Framework: "F1", Control: n} }
	return Mapping{
		SchemaVersion: 1,
		Frameworks: []FrameworkMeta{
			{Framework: "F1", Version: "v1", EffectiveDate: "2020-01-01"},
			{Framework: "F2", Version: "v2", EffectiveDate: "2021-01-01"},
		},
		Rules: []ruleMapping{
			{RuleID: "R-FAIL", Controls: []Control{fw("C1")}},
			{RuleID: "R-PASS", Controls: []Control{fw("C2")}},
			{RuleID: "R-UNK", Controls: []Control{fw("C3")}},
			{RuleID: "R-NA", Controls: []Control{fw("C4")}},
			{RuleID: "R-MIX-PASS", Controls: []Control{fw("C5")}},
			{RuleID: "R-MIX-UNK", Controls: []Control{fw("C5")}},
			{RuleID: "R-PASS2", Controls: []Control{{Framework: "F2", Control: "C1"}}},
			{RuleID: "R-FAIL2", Controls: []Control{{Framework: "F2", Control: "C1"}}},
			{RuleID: "R-NOFIND", Controls: []Control{{Framework: "F2", Control: "C2"}}},
		},
	}
}

func statusOf(res Result, framework, control string) (Status, []string) {
	for _, fr := range res.Frameworks {
		if fr.Framework != framework {
			continue
		}
		for _, c := range fr.Controls {
			if c.Control == control {
				return c.Status, c.Rules
			}
		}
	}
	return "", nil
}

// TestEvaluateStatusPaths proves status is derived only from findings, with the documented
// precedence: fail dominates, any unknown blocks a pass (never overstate), not-applicable is
// no evidence, and a control with no finding is not assessed.
func TestEvaluateStatusPaths(t *testing.T) {
	findings := []Finding{
		{RuleID: "R-FAIL", State: model.Fail},
		{RuleID: "R-PASS", State: model.Pass},
		{RuleID: "R-UNK", State: model.OutcomeUnknown},
		{RuleID: "R-NA", State: model.NotApplicable},
		{RuleID: "R-MIX-PASS", State: model.Pass},
		{RuleID: "R-MIX-UNK", State: model.OutcomeUnknown},
		{RuleID: "R-PASS2", State: model.Pass},
		{RuleID: "R-FAIL2", State: model.Fail},
		// R-NOFIND: no finding at all.
	}
	res := Evaluate(testMapping(), findings)

	cases := []struct {
		fw, control string
		want        Status
	}{
		{"F1", "C1", StatusFail},        // a failing finding
		{"F1", "C2", StatusPass},        // a passing finding
		{"F1", "C3", StatusNotAssessed}, // unknown
		{"F1", "C4", StatusNotAssessed}, // not-applicable only = no evidence
		{"F1", "C5", StatusNotAssessed}, // pass + unknown -> never overstate
		{"F2", "C1", StatusFail},        // fail dominates a co-mapped pass
		{"F2", "C2", StatusNotAssessed}, // mapped rule produced no finding
	}
	for _, c := range cases {
		got, _ := statusOf(res, c.fw, c.control)
		if got != c.want {
			t.Errorf("%s/%s = %q, want %q", c.fw, c.control, got, c.want)
		}
	}
}

// TestNeverPassWithoutBackingFinding is the ADR-0034 never-overstate guarantee: no control
// is ever reported pass without a rule that produced a passing finding, and no status is
// ever "compliant".
func TestNeverPassWithoutBackingFinding(t *testing.T) {
	// Deliberately pass NO findings: every mapped control must be not-assessed.
	res := Evaluate(testMapping(), nil)
	for _, fr := range res.Frameworks {
		for _, c := range fr.Controls {
			if c.Status == StatusPass || c.Status == StatusFail {
				t.Errorf("CRITICAL: %s/%s = %q with no findings; must be not_assessed", fr.Framework, c.Control, c.Status)
			}
			if string(c.Status) == "compliant" {
				t.Errorf("status must never be 'compliant'")
			}
		}
		if fr.Passed != 0 || fr.Failed != 0 {
			t.Errorf("%s: passed=%d failed=%d with no findings, want 0/0", fr.Framework, fr.Passed, fr.Failed)
		}
	}

	// With findings, any pass control must have a backing rule that actually passed.
	passFindings := []Finding{{RuleID: "R-PASS", State: model.Pass}}
	res2 := Evaluate(testMapping(), passFindings)
	st, rules := statusOf(res2, "F1", "C2")
	if st != StatusPass || len(rules) == 0 {
		t.Fatalf("C2 = %q rules=%v, want pass with backing rules", st, rules)
	}
	if rules[0] != "R-PASS" {
		t.Errorf("backing rule = %v, want R-PASS", rules)
	}
}

// TestCountsAndDeterminism checks the per-framework counts and deterministic control order.
func TestCountsAndDeterminism(t *testing.T) {
	findings := []Finding{
		{RuleID: "R-FAIL", State: model.Fail},
		{RuleID: "R-PASS", State: model.Pass},
		{RuleID: "R-UNK", State: model.OutcomeUnknown},
		{RuleID: "R-NA", State: model.NotApplicable},
		{RuleID: "R-MIX-PASS", State: model.Pass},
		{RuleID: "R-MIX-UNK", State: model.OutcomeUnknown},
	}
	res := Evaluate(testMapping(), findings)
	var f1 FrameworkResult
	for _, fr := range res.Frameworks {
		if fr.Framework == "F1" {
			f1 = fr
		}
	}
	if f1.Failed != 1 || f1.Passed != 1 || f1.NotAssessed != 3 {
		t.Errorf("F1 counts = %d/%d/%d, want 1/1/3", f1.Failed, f1.Passed, f1.NotAssessed)
	}
	// Frameworks keep mapping order; controls are sorted.
	if res.Frameworks[0].Framework != "F1" || res.Frameworks[1].Framework != "F2" {
		t.Errorf("framework order = %q,%q", res.Frameworks[0].Framework, res.Frameworks[1].Framework)
	}
	for i := 1; i < len(f1.Controls); i++ {
		if f1.Controls[i-1].Control > f1.Controls[i].Control {
			t.Errorf("controls not sorted: %v", f1.Controls)
		}
	}
}

func TestValidateRejectsBadMapping(t *testing.T) {
	bad := []Mapping{
		{SchemaVersion: 2, Frameworks: []FrameworkMeta{{Framework: "F", Version: "v", EffectiveDate: "d"}}},
		{SchemaVersion: 1},
		{SchemaVersion: 1, Frameworks: []FrameworkMeta{{Framework: "F", Version: "v", EffectiveDate: "d"}}, Rules: []ruleMapping{{RuleID: "R", Controls: []Control{{Framework: "OTHER", Control: "C"}}}}},
		{SchemaVersion: 1, Frameworks: []FrameworkMeta{{Framework: "F", Version: "v", EffectiveDate: "d"}}, Rules: []ruleMapping{{RuleID: "R"}}},
	}
	for i, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

// TestEveryShippedMappingReferencesEmbeddedRuleAndExistingIdentifier proves, for the
// committed mapping, that every rule mapping points at a rule that is actually embedded in a
// shipped pack, and that every control names a framework identifier declared in the mapping's
// frameworks list (with a non-empty control id). A mapping to a non-embedded rule, or to a
// framework that does not exist, is a drift the report would carry into customer-facing
// compliance output, so it fails here. This covers the identity-hygiene rules added to the
// mapping as well as the pre-existing core-p0 rules.
func TestEveryShippedMappingReferencesEmbeddedRuleAndExistingIdentifier(t *testing.T) {
	m, err := Load(packs.ComplianceMapping())
	if err != nil {
		t.Fatalf("shipped mapping did not load: %v", err)
	}
	ruleset, err := pack.LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	embedded := map[string]bool{}
	for _, r := range ruleset {
		embedded[r.ID] = true
	}
	frameworks := map[string]bool{}
	for _, f := range m.Frameworks {
		frameworks[f.Framework] = true
	}
	for _, r := range m.Rules {
		if !embedded[r.RuleID] {
			t.Errorf("mapping references rule %q, which is not embedded in any shipped pack", r.RuleID)
		}
		for _, c := range r.Controls {
			if !frameworks[c.Framework] {
				t.Errorf("rule %q maps to framework %q, which is not a declared framework identifier", r.RuleID, c.Framework)
			}
			if c.Control == "" {
				t.Errorf("rule %q has a control with an empty identifier", r.RuleID)
			}
		}
	}
}

// TestShippedMappingValidAndReconciles proves the committed ITTCsecProof mapping parses,
// validates, and references only rule ids that exist in the shipped detection packs, so the
// mapping cannot silently drift from the rules.
func TestShippedMappingValidAndReconciles(t *testing.T) {
	m, err := Load(packs.ComplianceMapping())
	if err != nil {
		t.Fatalf("shipped mapping did not load: %v", err)
	}
	ruleset, err := pack.LoadBuiltinAll(packs.FS, nil)
	if err != nil {
		t.Fatalf("load builtin packs: %v", err)
	}
	known := map[string]bool{}
	for _, r := range ruleset {
		known[r.ID] = true
	}
	if err := m.ValidateAgainstRules(known); err != nil {
		t.Errorf("shipped mapping drifted from the rules: %v", err)
	}
	if len(m.Frameworks) != 6 {
		t.Errorf("want the six named frameworks, got %d", len(m.Frameworks))
	}
}
