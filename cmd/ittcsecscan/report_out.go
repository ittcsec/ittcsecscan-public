package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ittcsec/ittcsecscan/internal/compliance"
	"github.com/ittcsec/ittcsecscan/internal/graph"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/report"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/version"
	"github.com/ittcsec/ittcsecscan/packs"
)

// buildReportInput assembles the report engine's input from the scan report and the
// aggregated analysis outputs. Provider coverage carries the real completeness records
// so the report's coverage and blind-spot statement is built from real data.
func buildReportInput(id store.TenantID, rep scan.Report, findings []pipeline.RankedFinding, classifications []model.Classification, paths []pipeline.RankedPath, cuts []model.CutSet, identity graph.EffectiveResult, diff store.Diff) report.Input {
	in := report.Input{
		Tenant:            id.String(),
		ToolVersion:       version.Get().Version,
		Findings:          findings,
		Paths:             paths,
		Cuts:              cuts,
		Classifications:   classifications,
		IdentityGrants:    identity.Grants,
		IdentityComplete:  identity.Complete,
		IdentityGaps:      identity.Gaps,
		ChangeScanID:      diff.ScanID,
		EntityChanges:     entityChanges(diff),
		EdgeChanges:       edgeChanges(diff),
		ComplianceMapping: loadComplianceMapping(),
	}
	for _, p := range rep.Providers {
		pc := report.ProviderCoverage{
			Provider:      string(p.Provider),
			Account:       p.Account,
			Authenticated: p.AuthError == nil,
			Records:       p.Completeness,
		}
		if p.AuthError != nil {
			pc.AuthError = redact.String(p.AuthError.Error())
		}
		in.Providers = append(in.Providers, pc)
	}
	return in
}

// loadComplianceMapping parses the embedded, release-signed ITTCsecProof mapping content
// (ADR-0034). The mapping is validated by tests at build time, so a parse failure here is a
// build defect; the scan still succeeds with an empty compliance section (reported honestly
// as "no compliance mapping loaded") rather than failing the whole report.
func loadComplianceMapping() compliance.Mapping {
	m, err := compliance.Load(packs.ComplianceMapping())
	if err != nil {
		return compliance.Mapping{}
	}
	return m
}

// entityChanges and edgeChanges map the store's diff deltas onto the report input types.
// Build sanitizes the strings; here they are passed through unchanged.
func entityChanges(d store.Diff) []report.EntityChange {
	out := make([]report.EntityChange, 0, len(d.Entities))
	for _, e := range d.Entities {
		out = append(out, report.EntityChange{Change: e.Change, Type: string(e.Type), Entity: e.NativeID, Name: e.Name})
	}
	return out
}

func edgeChanges(d store.Diff) []report.EdgeChange {
	out := make([]report.EdgeChange, 0, len(d.Edges))
	for _, e := range d.Edges {
		out = append(out, report.EdgeChange{Change: e.Change, Kind: string(e.Kind), Source: e.Source, Target: e.Target})
	}
	return out
}

// writeReports renders the frozen report to all five formats and writes them to dir.
// Files are 0600: a report carries finding data and is not world-readable by default.
func writeReports(w io.Writer, dir string, r report.Report) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	formats := []struct {
		name string
		gen  func(report.Report) ([]byte, error)
	}{
		{"report.json", report.JSON},
		{"report.sarif.json", report.SARIF},
		{"report.html", report.HTML},
		{"report.docx", report.DOCX},
		{"report.pdf", report.PDF},
	}
	for _, f := range formats {
		b, err := f.gen(r)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), b, 0o600); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(w, "wrote %s (%d bytes)\n", f.name, len(b))
	}
	_, _ = fmt.Fprintf(w, "report hash: %s\n", r.Hash)
	return nil
}
