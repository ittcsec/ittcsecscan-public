package report

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/compliance"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

func testComplianceMapping(t *testing.T) compliance.Mapping {
	t.Helper()
	m, err := compliance.Load([]byte(`{
      "schema_version": 1,
      "frameworks": [
        {"framework":"ISO 27001","version":"2022","effective_date":"2022-10-25"}
      ],
      "rules": [
        {"rule_id":"CORE-P0-STORAGE-PUBLIC-AWS","controls":[{"framework":"ISO 27001","control":"A.8.3"}]},
        {"rule_id":"CORE-P0-DATABASE-PUBLIC-AWS","controls":[{"framework":"ISO 27001","control":"A.5.15"}]}
      ]
    }`))
	if err != nil {
		t.Fatalf("load test mapping: %v", err)
	}
	return m
}

func rankedFinding(ruleID, native string, state model.Outcome) pipeline.RankedFinding {
	return pipeline.RankedFinding{
		Finding: model.Finding{Rule: model.RuleRef{RuleID: ruleID}, State: state},
		Native:  native,
	}
}

// TestComplianceSectionBuildsAndRenders proves the ITTCsecProof section derives per-control
// status from findings, renders in the shared lines, and keeps the report schema-valid.
func TestComplianceSectionBuildsAndRenders(t *testing.T) {
	r := Build(Input{
		Tenant: "t", ToolVersion: "v",
		ComplianceMapping: testComplianceMapping(t),
		Findings: []pipeline.RankedFinding{
			rankedFinding("CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::pub", model.Fail),
			rankedFinding("CORE-P0-DATABASE-PUBLIC-AWS", "arn:aws:rds:db", model.OutcomeUnknown),
		},
	})
	if len(r.Compliance.Frameworks) != 1 {
		t.Fatalf("frameworks = %d, want 1", len(r.Compliance.Frameworks))
	}
	fw := r.Compliance.Frameworks[0]
	if fw.Framework != "ISO 27001" || fw.Version != "2022" {
		t.Errorf("framework meta = %+v", fw)
	}
	if fw.Failed != 1 || fw.NotAssessed != 1 || fw.Passed != 0 {
		t.Errorf("counts = %d/%d/%d, want failed 1 / not-assessed 1 / passed 0", fw.Failed, fw.Passed, fw.NotAssessed)
	}
	statuses := map[string]string{}
	for _, c := range fw.Controls {
		statuses[c.Control] = c.Status
	}
	if statuses["A.8.3"] != "fail" {
		t.Errorf("A.8.3 = %q, want fail (backed by a failing finding)", statuses["A.8.3"])
	}
	if statuses["A.5.15"] != "not_assessed" {
		t.Errorf("A.5.15 = %q, want not_assessed (unknown finding)", statuses["A.5.15"])
	}

	var sb strings.Builder
	for _, ln := range reportLines(r) {
		sb.WriteString(ln.Text + "\n")
	}
	out := sb.String()
	for _, want := range []string{"Compliance evidence (ITTCsecProof)", "never a certification", "ISO 27001 (2022", "A.8.3: fail", "A.5.15: not_assessed"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}
	if strings.Contains(out, "compliant") {
		t.Errorf("report must never render a 'compliant' verdict:\n%s", out)
	}

	b, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateJSON(schema.ModelReport, b); err != nil {
		t.Fatalf("report with compliance section violates the schema: %v\n%s", err, b)
	}
}

// TestComplianceNeverOverstatesInReport is the report-level never-overstate guarantee: a
// control whose only finding is a pass is pass, but with no findings at all every control is
// not assessed, never pass.
func TestComplianceNeverOverstatesInReport(t *testing.T) {
	passing := Build(Input{
		Tenant: "t", ToolVersion: "v", ComplianceMapping: testComplianceMapping(t),
		Findings: []pipeline.RankedFinding{rankedFinding("CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::ok", model.Pass)},
	})
	if s := controlStatusIn(passing, "ISO 27001", "A.8.3"); s != "pass" {
		t.Errorf("A.8.3 with a passing finding = %q, want pass", s)
	}

	none := Build(Input{Tenant: "t", ToolVersion: "v", ComplianceMapping: testComplianceMapping(t)})
	for _, c := range none.Compliance.Frameworks[0].Controls {
		if c.Status == "pass" || c.Status == "fail" {
			t.Errorf("CRITICAL: %s = %q with no findings; must be not_assessed", c.Control, c.Status)
		}
	}
}

// TestComplianceEmptyMappingIsHonest proves an absent mapping yields an empty section and
// the honest "no compliance mapping loaded" line, never a fabricated framework.
func TestComplianceEmptyMappingIsHonest(t *testing.T) {
	r := Build(Input{Tenant: "t", ToolVersion: "v"})
	if len(r.Compliance.Frameworks) != 0 {
		t.Errorf("empty mapping must yield no frameworks, got %d", len(r.Compliance.Frameworks))
	}
	var sb strings.Builder
	for _, ln := range reportLines(r) {
		sb.WriteString(ln.Text + "\n")
	}
	if !strings.Contains(sb.String(), "no compliance mapping loaded") {
		t.Error("missing honest empty-mapping line")
	}
	b, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateJSON(schema.ModelReport, b); err != nil {
		t.Fatalf("report with empty compliance section violates the schema: %v", err)
	}
}

func controlStatusIn(r Report, framework, control string) string {
	for _, fw := range r.Compliance.Frameworks {
		if fw.Framework != framework {
			continue
		}
		for _, c := range fw.Controls {
			if c.Control == control {
				return c.Status
			}
		}
	}
	return ""
}
