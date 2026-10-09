package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/schema"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

func fixtureResults() []pipeline.RankedFinding {
	rf := func(id, entity string, state model.Outcome, risk int, conf model.Confidence, detail string) pipeline.RankedFinding {
		return pipeline.RankedFinding{
			Finding: model.Finding{Rule: model.RuleRef{RuleID: id}, Entity: model.StableID(entity), State: state, Risk: risk, Confidence: conf, Detail: detail},
			Native:  entity,
			Basis:   []string{"severity=75(weight 50)", "confidence(discount)", "model_version=1"},
		}
	}
	// Given risk-descending (as the pipeline would order them).
	return []pipeline.RankedFinding{
		rf("CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS", "arn:aws:ec2:u:1:instance/i-open", model.Fail, 60, 80, "exposed on all ports"),
		rf("CORE-P0-STORAGE-PUBLIC-AWS", "arn:aws:s3:::pub", model.OutcomeUnknown, 0, 0, "coverage gap"),
		rf("CORE-P0-DATABASE-PUBLIC-AWS", "arn:aws:rds:db-ok", model.Pass, 0, 0, ""),
		rf("CORE-P0-STORAGE-PUBLIC-GCP", "//storage.googleapis.com/b", model.NotApplicable, 0, 0, ""),
	}
}

func completeReport() scan.Report {
	return scan.Report{Authenticated: 1, ScanID: 9, Providers: []scan.ProviderResult{{
		Provider: model.AWS, Account: "acct-1",
		Completeness: []collect.Completeness{{Service: "ec2.instances", Region: collect.Global, Scope: collect.Scope{Account: "acct-1"}, Status: collect.Complete, Collected: 1}},
	}}}
}

// TestScanResultJSONWithFindingsMatchesSchema proves an analyzed scan's JSON still
// satisfies the scan schema (now with the optional findings section) and that
// not_applicable is counted but not listed.
func TestScanResultJSONWithFindingsMatchesSchema(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	var buf bytes.Buffer
	if err := writeScanResult(&buf, true, true, id, completeReport(), fixtureResults(), nil, nil, nil); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	if err := schema.ValidateJSON(schema.Scan, buf.Bytes()); err != nil {
		t.Fatalf("analyzed JSON violates scan schema: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "\"findings\"") || !strings.Contains(out, "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS") {
		t.Errorf("findings section missing: %s", out)
	}
	if strings.Contains(out, "CORE-P0-STORAGE-PUBLIC-GCP") {
		t.Errorf("not_applicable result should not be listed in items: %s", out)
	}
	if !strings.Contains(out, "\"not_applicable\": 1") {
		t.Errorf("not_applicable should be counted in totals: %s", out)
	}
}

// TestScanResultCollectOnlyOmitsFindings proves --collect-only produces the exact
// coverage-only JSON (no findings section), still schema-valid.
func TestScanResultCollectOnlyOmitsFindings(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	var buf bytes.Buffer
	if err := writeScanResult(&buf, true, false, id, completeReport(), nil, nil, nil, nil); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	if err := schema.ValidateJSON(schema.Scan, buf.Bytes()); err != nil {
		t.Fatalf("collect-only JSON violates scan schema: %v\n%s", err, buf.String())
	}
	if strings.Contains(buf.String(), "\"findings\"") {
		t.Errorf("collect-only output must omit the findings section: %s", buf.String())
	}
}

// TestScanResultTextListsActionableFindings proves the text view lists fail/unknown
// with the rule and a tally, and does not list not_applicable or pass individually.
func TestScanResultTextListsActionableFindings(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	var buf bytes.Buffer
	if err := writeScanResult(&buf, false, true, id, completeReport(), fixtureResults(), nil, nil, nil); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Findings:", "[FAIL]", "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS", "[UNKNOWN]"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "CORE-P0-STORAGE-PUBLIC-GCP") {
		t.Errorf("not_applicable listed in text: %s", out)
	}
}

// TestScanExitFindingsGate proves the exit precedence: --fail-on-findings makes a
// failing finding exit 6 and take precedence over a coverage gap; without the flag
// the exit reflects coverage only; collect-only never gates on findings.
func TestScanExitFindingsGate(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	fails := fixtureResults() // contains a Fail
	noFail := fails[1:]       // unknown, pass, not_applicable only
	incomplete := completeReport()
	incomplete.Providers[0].Completeness[0].Status = collect.Denied // a gap

	cases := []struct {
		name           string
		rep            scan.Report
		analyzed       bool
		failOnFindings bool
		findings       []pipeline.RankedFinding
		want           exitcode.Code
	}{
		{"gate on: fail beats gap", incomplete, true, true, fails, exitcode.FindingsAtThreshold},
		{"gate on: fail, complete", completeReport(), true, true, fails, exitcode.FindingsAtThreshold},
		{"gate off: fail, complete -> ok", completeReport(), true, false, fails, exitcode.OK},
		{"gate on: no fail, gap -> incomplete", incomplete, true, true, noFail, exitcode.ScanIncomplete},
		{"collect-only: fail ignored, complete -> ok", completeReport(), false, true, nil, exitcode.OK},
		{"auth-failed dominates", scan.Report{Authenticated: 0, Providers: []scan.ProviderResult{{Provider: model.AWS}}}, true, true, fails, exitcode.AuthFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := exitcode.From(scanExit(id, c.rep, c.analyzed, c.failOnFindings, c.findings))
			if got != c.want {
				t.Errorf("exit = %s, want %s", got, c.want)
			}
		})
	}
}

func fixtureClassifications() []model.Classification {
	return []model.Classification{
		{Entity: "aaaa", Label: string(model.SensitivityHigh), Method: "resource_nature=key_material", Confidence: 70},
		{Entity: "bbbb", Label: string(model.SensitivityUnknown), Method: "resource_nature=data_store; no sensitivity signal in metadata", Confidence: 15},
	}
}

// TestScanResultClassificationInJSON proves an analyzed scan's JSON carries the
// classification section (totals + items) and still satisfies the scan schema.
func TestScanResultClassificationInJSON(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	var buf bytes.Buffer
	if err := writeScanResult(&buf, true, true, id, completeReport(), fixtureResults(), fixtureClassifications(), nil, nil); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	if err := schema.ValidateJSON(schema.Scan, buf.Bytes()); err != nil {
		t.Fatalf("analyzed JSON violates scan schema: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "\"classification\"") || !strings.Contains(out, "\"high\": 1") || !strings.Contains(out, "\"unknown\": 1") {
		t.Errorf("classification section/totals missing: %s", out)
	}
}

// TestScanResultClassificationText proves the text view carries a classification tally.
func TestScanResultClassificationText(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	var buf bytes.Buffer
	if err := writeScanResult(&buf, false, true, id, completeReport(), fixtureResults(), fixtureClassifications(), nil, nil); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	if !strings.Contains(buf.String(), "Classification: 1 high, 0 moderate, 0 low, 1 unknown") {
		t.Errorf("classification tally missing: %s", buf.String())
	}
}
