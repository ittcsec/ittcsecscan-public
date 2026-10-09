package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// findingsSection is the analysis part of a scan's JSON output. not_applicable
// results are counted in Totals but not listed in Items (they are the rules that
// did not apply to this scan's providers, not findings about the tenant).
type findingsSection struct {
	Totals findingTotals `json:"totals"`
	Items  []findingJSON `json:"items"`
}

type findingTotals struct {
	Fail          int `json:"fail"`
	Unknown       int `json:"unknown"`
	Error         int `json:"error"`
	Pass          int `json:"pass"`
	NotApplicable int `json:"not_applicable"`
}

// findingJSON is the stable, product-facing shape of one finding, including its
// computed risk and the transparent risk basis (ADR-0027), so a reader sees exactly
// why it ranked where it did. It is a small projection of the richer model; the full
// grounding and trace are rendered by the report engine.
type findingJSON struct {
	Rule       string   `json:"rule"`
	Entity     string   `json:"entity"`
	State      string   `json:"state"`
	Risk       int      `json:"risk"`
	Confidence int      `json:"confidence"`
	RiskBasis  []string `json:"risk_basis"`
	Detail     string   `json:"detail,omitempty"`
}

func tallyFindings(fs []pipeline.RankedFinding) findingTotals {
	var t findingTotals
	for _, r := range fs {
		switch r.Finding.State {
		case model.Fail:
			t.Fail++
		case model.OutcomeUnknown:
			t.Unknown++
		case model.OutcomeError:
			t.Error++
		case model.Pass:
			t.Pass++
		case model.NotApplicable:
			t.NotApplicable++
		}
	}
	return t
}

// toFindingsSection projects the risk-ordered findings into the wire shape (order
// preserved: highest risk first). Every state is counted, but not_applicable results
// are omitted from the item list. Entity, detail, and basis are redacted as defence in
// depth, so no credential material can reach the output.
func toFindingsSection(fs []pipeline.RankedFinding) *findingsSection {
	sec := &findingsSection{Totals: tallyFindings(fs), Items: []findingJSON{}}
	for _, r := range fs {
		if r.Finding.State == model.NotApplicable {
			continue
		}
		sec.Items = append(sec.Items, findingJSON{
			Rule:       r.Finding.Rule.RuleID,
			Entity:     redact.String(r.Native),
			State:      string(r.Finding.State),
			Risk:       r.Finding.Risk,
			Confidence: int(r.Finding.Confidence),
			RiskBasis:  redactAll(r.Basis),
			Detail:     redact.String(r.Finding.Detail),
		})
	}
	return sec
}

// writeFindingsText appends the human-readable findings section: a tally line, then
// one block per actionable finding (fail, error, unknown) in risk order, with the
// risk score and its basis. not_applicable and pass are counted but not listed.
func writeFindingsText(b *strings.Builder, fs []pipeline.RankedFinding) {
	t := tallyFindings(fs)
	fmt.Fprintf(b, "Findings: %d fail, %d unknown, %d error, %d pass (%d not applicable)\n",
		t.Fail, t.Unknown, t.Error, t.Pass, t.NotApplicable)
	actionable := map[model.Outcome]bool{model.Fail: true, model.OutcomeError: true, model.OutcomeUnknown: true}
	for _, r := range fs {
		if !actionable[r.Finding.State] {
			continue
		}
		fmt.Fprintf(b, "  [%s] risk=%d %s entity=%s confidence=%d\n",
			strings.ToUpper(string(r.Finding.State)), r.Finding.Risk, r.Finding.Rule.RuleID, redact.String(r.Native), int(r.Finding.Confidence))
		fmt.Fprintf(b, "        risk basis: %s\n", redact.String(strings.Join(r.Basis, "; ")))
		if r.Finding.Detail != "" {
			fmt.Fprintf(b, "        %s\n", redact.String(r.Finding.Detail))
		}
	}
}

// redactAll redacts each string in a slice (defence in depth for the risk basis).
func redactAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = redact.String(s)
	}
	return out
}

// classificationSection is the classification part of a scan's JSON output: totals
// by sensitivity, then one item per classified asset (ordered by entity).
type classificationSection struct {
	Totals sensitivityTotals    `json:"totals"`
	Items  []classificationItem `json:"items"`
}

type sensitivityTotals struct {
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type classificationItem struct {
	Entity      string `json:"entity"`
	Sensitivity string `json:"sensitivity"`
	Confidence  int    `json:"confidence"`
	Method      string `json:"method"`
}

func tallySensitivity(cs []model.Classification) sensitivityTotals {
	var t sensitivityTotals
	for _, c := range cs {
		switch model.Sensitivity(c.Label) {
		case model.SensitivityHigh:
			t.High++
		case model.SensitivityModerate:
			t.Moderate++
		case model.SensitivityLow:
			t.Low++
		case model.SensitivityUnknown:
			t.Unknown++
		}
	}
	return t
}

// toClassificationSection projects classifications into the wire shape, ordered by
// entity for determinism. Method and entity are redacted as defence in depth.
func toClassificationSection(cs []model.Classification) *classificationSection {
	sorted := append([]model.Classification(nil), cs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Entity < sorted[j].Entity })
	sec := &classificationSection{Totals: tallySensitivity(cs), Items: []classificationItem{}}
	for _, c := range sorted {
		sec.Items = append(sec.Items, classificationItem{
			Entity:      string(c.Entity),
			Sensitivity: c.Label,
			Confidence:  int(c.Confidence),
			Method:      redact.String(c.Method),
		})
	}
	return sec
}

// writeClassificationText appends the human-readable classification tally.
func writeClassificationText(b *strings.Builder, cs []model.Classification) {
	t := tallySensitivity(cs)
	fmt.Fprintf(b, "Classification: %d high, %d moderate, %d low, %d unknown\n", t.High, t.Moderate, t.Low, t.Unknown)
}

// hasFailFindings reports whether any finding is a fail, for --fail-on-findings.
func hasFailFindings(fs []pipeline.RankedFinding) bool {
	for _, r := range fs {
		if r.Finding.State == model.Fail {
			return true
		}
	}
	return false
}
