package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

func storagePlan() *remediate.GeneratedPlan {
	e := model.Entity{ID: "sid1", Provider: model.AWS, Type: model.NodeDataStore, Name: "pub", NativeID: "arn:aws:s3:::pub", Attributes: map[string]string{"policy_is_public": "true"}}
	p := remediate.Plan(model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, e)
	return &p
}

func computeGapPlan() *remediate.GeneratedPlan {
	e := model.Entity{ID: "sid3", Provider: model.AWS, Type: model.NodeCompute, Name: "i-123", NativeID: "i-123"}
	p := remediate.Plan(model.RuleRef{RuleID: "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS"}, e)
	return &p
}

// fixtureInput is a report input carrying a secret and an em dash in customer-facing
// strings, a coverage gap, a finding, a path, a cut, and a classification.
func fixtureInput() Input {
	return Input{
		Tenant: "aaaaaaaaaaaaaaaaaaaaaaaaaa", ToolVersion: "v1.2.3",
		Started: "2026-09-26T00:00:00Z", Completed: "2026-09-26T00:10:00Z",
		Providers: []ProviderCoverage{{
			Provider: "aws", Account: "acct-1", Authenticated: true,
			Records: []collect.Completeness{
				{Service: "s3.bucketConfig", Status: collect.Complete, Collected: 3},
				{Service: "securityhub", Status: collect.Denied, Reason: "not subscribed"},
			},
		}},
		Findings: []pipeline.RankedFinding{{
			Finding: model.Finding{Rule: model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, Entity: "sid1", State: model.Fail, Risk: 35, Confidence: 95, Detail: "public bucket — leaked key AKIAIOSFODNN7EXAMPLE in policy"},
			Native:  "arn:aws:s3:::pub",
			Basis:   []string{"severity=75(weight 50)", "confidence=95(discount)"},
			Plan:    storagePlan(),
		}, {
			Finding: model.Finding{Rule: model.RuleRef{RuleID: "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS"}, Entity: "sid3", State: model.Fail, Risk: 31, Confidence: 80},
			Native:  "i-123",
			Basis:   []string{"severity=75(weight 50)"},
			Plan:    computeGapPlan(),
		}, {
			Finding: model.Finding{Rule: model.RuleRef{RuleID: "CORE-P0-KMS-ROTATION-AWS"}, Entity: "sid2", State: model.NotApplicable, Risk: 0, Confidence: 0},
			Native:  "arn:aws:kms:k",
		}},
		Paths: []pipeline.RankedPath{{
			Path: model.AttackPath{Entry: "e", Target: "t", Score: 100, Confidence: 80, Steps: []model.PathStep{{Node: "e"}, {Node: "t", Via: model.EdgeAssumes, Technique: "T1078"}}},
			Risk: 72, Basis: []string{"severity=100(weight 50)"},
		}},
		Cuts:            []model.CutSet{{Changes: []model.CutChange{{Source: "e", Target: "t", Kind: model.EdgeAssumes, Description: "revoke the assume-role"}}, PathsRemoved: 1, RiskReduction: 72, Effort: 3, Disruption: 4}},
		Classifications: []model.Classification{{Entity: "sid1", Label: "unknown", Method: "resource_nature=data_store", Confidence: 15}},
	}
}

func TestJSONDeterministicAndHashed(t *testing.T) {
	r := Build(fixtureInput())
	a, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := JSON(Build(fixtureInput()))
	if !bytes.Equal(a, b) {
		t.Error("JSON render is not deterministic")
	}
	if r.Hash == "" {
		t.Error("report has no content hash")
	}
}

// TestCoveragePrecedesFindings proves the coverage section comes before findings in the
// JSON (by model field order), and that the gap is stated.
func TestCoveragePrecedesFindings(t *testing.T) {
	out, _ := JSON(Build(fixtureInput()))
	s := string(out)
	if strings.Index(s, "\"coverage\"") > strings.Index(s, "\"findings\"") {
		t.Error("coverage must precede findings")
	}
	if !strings.Contains(s, "securityhub:denied") {
		t.Errorf("coverage gap not stated: %s", s)
	}
	if strings.Contains(s, "\"complete\": true") {
		t.Error("coverage with a denied read must not report complete")
	}
}

// TestRemediationIsRealOrHonestGap proves RP-1 is closed: a failing finding with a
// verified template shows real, doc-verified guidance (portal, CLI, IaC, privilege,
// verification, plan hash), and a failing finding with no template shows an honest
// named gap and never fabricated actions.
func TestRemediationIsRealOrHonestGap(t *testing.T) {
	r := Build(fixtureInput())
	var storage, compute *Finding
	for i := range r.Findings {
		switch r.Findings[i].Rule {
		case "CORE-P0-STORAGE-PUBLIC-AWS":
			storage = &r.Findings[i]
		case "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS":
			compute = &r.Findings[i]
		}
	}
	if storage == nil || compute == nil {
		t.Fatal("expected both the storage and compute findings")
	}

	// Real guidance for the templated rule.
	if !storage.Remediation.Available {
		t.Error("storage finding should carry real remediation")
	}
	if len(storage.Remediation.Actions) == 0 || len(storage.Remediation.Actions[0].CLI) == 0 || storage.Remediation.Actions[0].IaC == "" {
		t.Error("storage remediation is missing real portal/CLI/IaC guidance")
	}
	if storage.Remediation.PlanHash == "" || len(storage.Remediation.Verification) == 0 {
		t.Error("storage remediation missing plan hash or verification")
	}

	// Honest named gap for the compute rule: no actions fabricated.
	if compute.Remediation.Available {
		t.Error("compute finding must be an honest gap, not available")
	}
	if len(compute.Remediation.Actions) != 0 {
		t.Error("compute gap must carry no fabricated actions")
	}
	if !strings.Contains(compute.Remediation.Statement, "RP-6") {
		t.Errorf("compute gap does not name the tracked gap: %q", compute.Remediation.Statement)
	}
}

// TestHonestyGateRedactsAndStripsDashes is the safety-critical proving test: no rendered
// format leaks the secret or emits a forbidden dash, and the secret is redacted.
func TestHonestyGateRedactsAndStripsDashes(t *testing.T) {
	r := Build(fixtureInput())
	jsonOut, _ := JSON(r)
	sarifOut, _ := SARIF(r)
	for name, out := range map[string][]byte{"json": jsonOut, "sarif": sarifOut} {
		s := string(out)
		if strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%s leaked the secret", name)
		}
		if !strings.Contains(s, "[REDACTED]") {
			t.Errorf("%s did not redact the secret", name)
		}
		if containsForbiddenDash(s) {
			t.Errorf("%s emitted a forbidden em/en dash", name)
		}
	}
}

// TestIdenticalFindingsAcrossFormats proves JSON and SARIF carry the same finding set.
func TestIdenticalFindingsAcrossFormats(t *testing.T) {
	r := Build(fixtureInput())
	jsonRules := map[string]bool{}
	for _, f := range r.Findings {
		jsonRules[f.Rule+"|"+f.Entity] = true
	}
	sarifOut, _ := SARIF(r)
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID     string         `json:"ruleId"`
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifOut, &doc); err != nil {
		t.Fatal(err)
	}
	sarifSet := map[string]bool{}
	for _, res := range doc.Runs[0].Results {
		sarifSet[res.RuleID+"|"+res.Properties["entity"].(string)] = true
	}
	if len(jsonRules) != len(sarifSet) {
		t.Errorf("finding count differs: json %d, sarif %d", len(jsonRules), len(sarifSet))
	}
	for k := range jsonRules {
		if !sarifSet[k] {
			t.Errorf("finding %q in JSON missing from SARIF", k)
		}
	}
}

// TestNotApplicableExcludedFromFindings proves not_applicable results are not listed as
// findings about the tenant.
func TestNotApplicableExcludedFromFindings(t *testing.T) {
	r := Build(fixtureInput())
	for _, f := range r.Findings {
		if f.Rule == "CORE-P0-KMS-ROTATION-AWS" {
			t.Error("a not_applicable result was listed as a finding")
		}
	}
}

// TestJSONMatchesReportSchema proves the JSON output satisfies the published report
// model schema.
func TestJSONMatchesReportSchema(t *testing.T) {
	out, err := JSON(Build(fixtureInput()))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateJSON(schema.ModelReport, out); err != nil {
		t.Fatalf("report JSON violates the report schema: %v\n%s", err, out)
	}
}
