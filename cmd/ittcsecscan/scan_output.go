package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
)

// scanJSON is the wire form of a scan result (schemas/cli/v1/scan.schema.json).
type scanJSON struct {
	SchemaVersion int                `json:"schema_version"`
	Tenant        string             `json:"tenant"`
	ScanID        int64              `json:"scan_id"`
	Outcome       string             `json:"outcome"`
	Authenticated int                `json:"authenticated"`
	DroppedEdges  int                `json:"dropped_edges"`
	Providers     []scanProviderJSON `json:"providers"`
	// Findings and Classification are present when the scan ran the analysis
	// pipeline (the default; suppressed by --collect-only). Both are omitted for a
	// collect-only scan.
	Findings       *findingsSection       `json:"findings,omitempty"`
	Classification *classificationSection `json:"classification,omitempty"`
	Attack         *attackSection         `json:"attack,omitempty"`
}

type scanProviderJSON struct {
	Provider      string                 `json:"provider"`
	Account       string                 `json:"account,omitempty"`
	Authenticated bool                   `json:"authenticated"`
	AuthError     string                 `json:"auth_error,omitempty"`
	Coverage      []collect.Completeness `json:"coverage"`
}

// scanOutcome labels a report the same way scanExit maps it to an exit code, so
// the printed outcome and the process status can never disagree.
func scanOutcome(rep scan.Report) string {
	switch {
	case rep.Authenticated == 0:
		return "auth-failed"
	case !rep.FullCoverage():
		return "incomplete"
	default:
		return "complete"
	}
}

func toScanJSON(id store.TenantID, rep scan.Report) scanJSON {
	out := scanJSON{
		SchemaVersion: 1,
		Tenant:        id.String(),
		ScanID:        rep.ScanID,
		Outcome:       scanOutcome(rep),
		Authenticated: rep.Authenticated,
		DroppedEdges:  rep.DroppedEdges,
	}
	for _, p := range rep.Providers {
		pj := scanProviderJSON{
			Provider:      string(p.Provider),
			Account:       p.Account,
			Authenticated: p.AuthError == nil,
			Coverage:      p.Completeness,
		}
		if p.AuthError != nil {
			// The auth seam already scrubs the cause; redact again as defence in
			// depth so no credential material can reach the output.
			pj.AuthError = redact.String(p.AuthError.Error())
		}
		if pj.Coverage == nil {
			pj.Coverage = []collect.Completeness{}
		}
		out.Providers = append(out.Providers, pj)
	}
	return out
}

// writeScanResult prints the scan result including analysis findings, JSON or
// text. When analyzed is false (a --collect-only scan) it is exactly the coverage
// report; otherwise it appends the findings section. Both forms report the same
// totals and outcome, so machine and human views agree with each other and with
// the exit code.
func writeScanResult(w io.Writer, asJSON, analyzed bool, id store.TenantID, rep scan.Report, results []pipeline.RankedFinding, classifications []model.Classification, paths []pipeline.RankedPath, cuts []model.CutSet) error {
	if asJSON {
		sj := toScanJSON(id, rep)
		if analyzed {
			sj.Findings = toFindingsSection(results)
			sj.Classification = toClassificationSection(classifications)
			sj.Attack = toAttackSection(paths, cuts)
		}
		return writeJSON(w, sj)
	}
	var b strings.Builder
	writeScanReportText(&b, id, rep)
	if analyzed {
		writeClassificationText(&b, classifications)
		writeAttackText(&b, paths, cuts)
		writeFindingsText(&b, results)
	}
	_, err := io.WriteString(w, termsafe.String(redact.String(b.String())))
	return err
}

// writeScanReport prints the coverage-only scan result, JSON or text. Both forms
// report the same outcome, so the machine-readable and human-readable views agree
// with each other and with the exit code.
func writeScanReport(w io.Writer, asJSON bool, id store.TenantID, rep scan.Report) error {
	if asJSON {
		return writeJSON(w, toScanJSON(id, rep))
	}
	var b strings.Builder
	writeScanReportText(&b, id, rep)
	_, err := io.WriteString(w, termsafe.String(redact.String(b.String())))
	return err
}

// writeScanReportText writes the human-readable coverage section into b.
func writeScanReportText(b *strings.Builder, id store.TenantID, rep scan.Report) {
	fmt.Fprintf(b, "Scan of tenant %s: %s\n", id, scanOutcome(rep))
	if rep.ScanID != 0 {
		fmt.Fprintf(b, "  scan id:       %d\n", rep.ScanID)
	}
	fmt.Fprintf(b, "  authenticated: %d of %d providers\n", rep.Authenticated, len(rep.Providers))
	if rep.DroppedEdges != 0 {
		fmt.Fprintf(b, "  dropped edges: %d (an endpoint was not collected)\n", rep.DroppedEdges)
	}
	for _, p := range rep.Providers {
		if p.AuthError != nil {
			fmt.Fprintf(b, "  %s: not authenticated (%s)\n", p.Provider, redact.String(p.AuthError.Error()))
			continue
		}
		fmt.Fprintf(b, "  %s: account %s\n", p.Provider, p.Account)
		for _, c := range p.Completeness {
			mark := "ok"
			if !c.Done() {
				mark = string(c.Status)
			}
			fmt.Fprintf(b, "    %-16s %-8s collected %d", c.Service, mark, c.Collected)
			if c.Reason != "" {
				fmt.Fprintf(b, " (%s)", c.Reason)
			}
			b.WriteByte('\n')
		}
	}
}
