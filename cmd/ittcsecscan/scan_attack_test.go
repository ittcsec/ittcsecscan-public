package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/schema"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

func fixtureAttack() ([]pipeline.RankedPath, []model.CutSet) {
	paths := []pipeline.RankedPath{{
		Path: model.AttackPath{
			Entry: "aaaa", Target: "bbbb", Score: 100, Confidence: 80,
			Steps: []model.PathStep{{Node: "aaaa", Technique: "T1190"}, {Node: "bbbb", Via: model.EdgeAssumes, Technique: "T1078"}},
		},
		Risk:  72,
		Basis: []string{"severity=100(weight 50)", "confidence=80(discount)", "model_version=1"},
	}}
	cuts := []model.CutSet{{
		Changes:      []model.CutChange{{Source: "aaaa", Target: "bbbb", Kind: model.EdgeAssumes, Description: "revoke the role assumption on this path"}},
		PathsRemoved: 1, RiskReduction: 80, Effort: 3, Disruption: 4,
	}}
	return paths, cuts
}

// TestScanResultAttackInJSON proves an analyzed scan's JSON carries the attack section
// (paths + ranked cuts) and still satisfies the scan schema.
func TestScanResultAttackInJSON(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	paths, cuts := fixtureAttack()
	var buf bytes.Buffer
	if err := writeScanResult(&buf, true, true, id, completeReport(), fixtureResults(), fixtureClassifications(), paths, cuts); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	if err := schema.ValidateJSON(schema.Scan, buf.Bytes()); err != nil {
		t.Fatalf("analyzed JSON violates scan schema: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "\"attack\"") || !strings.Contains(out, "T1078") || !strings.Contains(out, "\"risk_reduction\": 80") {
		t.Errorf("attack section missing content: %s", out)
	}
}

// TestScanResultAttackText proves the text view carries an attack-path summary and a
// ranked cut line.
func TestScanResultAttackText(t *testing.T) {
	id, _ := store.ParseTenantID(canonicalTenantID)
	paths, cuts := fixtureAttack()
	var buf bytes.Buffer
	if err := writeScanResult(&buf, false, true, id, completeReport(), fixtureResults(), fixtureClassifications(), paths, cuts); err != nil {
		t.Fatalf("writeScanResult: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Attack paths: 1 (1 cut candidates)") || !strings.Contains(out, "cut: assumes") {
		t.Errorf("attack text summary missing: %s", out)
	}
}
