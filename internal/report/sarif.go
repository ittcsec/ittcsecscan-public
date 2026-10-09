package report

import "encoding/json"

// SARIF renders the report as SARIF 2.1.0 JSON, a pure projection of the same frozen
// model. It emits one result per report finding, so the finding set is identical to the
// JSON format's (the design's identical-findings requirement, guaranteed by
// deriving from one model). Coverage rides on run.properties. Deterministic.
func SARIF(r Report) ([]byte, error) {
	driver := sarifDriver{Name: "ittcsecscan", Version: r.ToolVersion, Rules: sarifRules(r)}
	run := sarifRun{
		Tool:       sarifTool{Driver: driver},
		Results:    sarifResults(r),
		Properties: map[string]any{"coverage": r.Coverage, "report_hash": r.Hash, "remediation": r.Remediation},
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID     string         `json:"ruleId"`
	Level      string         `json:"level"`
	Message    sarifMessage   `json:"message"`
	Properties map[string]any `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// sarifRules is the deduplicated set of rule ids, in finding order.
func sarifRules(r Report) []sarifRule {
	seen := map[string]bool{}
	out := []sarifRule{}
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			out = append(out, sarifRule{ID: f.Rule})
		}
	}
	return out
}

func sarifResults(r Report) []sarifResult {
	out := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		msg := f.Detail
		if msg == "" {
			msg = f.Rule
		}
		props := map[string]any{
			"entity": f.Entity, "risk": f.Risk, "confidence": f.Confidence,
			"state": f.State, "risk_basis": f.RiskBasis,
			"remediation_available": f.Remediation.Available,
			"remediation":           f.Remediation.Statement,
		}
		if f.Remediation.Available {
			props["remediation_plan_hash"] = f.Remediation.PlanHash
			props["remediation_reversible"] = f.Remediation.Reversible
			cli := []string{}
			for _, a := range f.Remediation.Actions {
				cli = append(cli, a.CLI...)
			}
			if len(cli) > 0 {
				props["remediation_cli"] = cli
			}
		}
		out = append(out, sarifResult{
			RuleID:     f.Rule,
			Level:      sarifLevel(f.State),
			Message:    sarifMessage{Text: msg},
			Properties: props,
		})
	}
	return out
}

// sarifLevel maps a finding state to a SARIF level. A pass is "none"; an unknown or
// error is "note" (we could not determine it, never asserted as a clean result); a fail
// is "error".
func sarifLevel(state string) string {
	switch state {
	case "fail":
		return "error"
	case "unknown", "error":
		return "note"
	}
	return "none"
}
