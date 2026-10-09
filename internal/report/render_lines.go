package report

import (
	"strconv"
	"strings"
)

// reportLine is one line of the human-readable report. The three text-shaped formats
// (HTML, DOCX, PDF) all render from this one ordered list, so they carry identical
// content and cannot diverge; each applies its own escaping on top. Every Text here is
// already sanitized (it comes from the frozen model), joined only with ASCII literals.
type reportLine struct {
	Heading bool
	Text    string
}

// reportLines renders the frozen model to an ordered line list, coverage first, then
// findings, attack paths, cut candidates, classifications, and the remediation gap.
func reportLines(r Report) []reportLine {
	var ls []reportLine
	h := func(s string) { ls = append(ls, reportLine{Heading: true, Text: s}) }
	p := func(s string) { ls = append(ls, reportLine{Text: s}) }

	h("ittcsecscan report")
	p("tenant: " + r.Tenant + "   tool: " + r.ToolVersion)
	if r.Started != "" {
		p("scan: " + r.Started + " to " + r.Completed)
	}
	p("report hash: " + r.Hash)

	h("Coverage and blind spots")
	if r.Coverage.Complete {
		p("coverage: complete")
	} else {
		p("coverage: INCOMPLETE (blind spots listed below); findings are a floor, not exhaustive")
	}
	for _, g := range r.Coverage.Gaps {
		p("blind spot: " + g)
	}
	for _, pv := range r.Coverage.Providers {
		auth := "authenticated"
		if !pv.Authenticated {
			auth = "NOT authenticated: " + pv.AuthError
		}
		p("provider " + pv.Provider + " (" + pv.Account + "): " + auth)
		for _, rec := range pv.Records {
			line := "   " + rec.Service + " [" + rec.Status + "] collected " + strconv.Itoa(rec.Collected)
			if rec.Reason != "" {
				line += " (" + rec.Reason + ")"
			}
			p(line)
		}
	}

	h("Findings (highest risk first)")
	if len(r.Findings) == 0 {
		p("no findings")
	}
	for _, f := range r.Findings {
		p("[" + strings.ToUpper(f.State) + "] risk=" + strconv.Itoa(f.Risk) + " " + f.Rule + " on " + f.Entity + " (confidence " + strconv.Itoa(f.Confidence) + ")")
		p("   risk basis: " + strings.Join(f.RiskBasis, "; "))
		if len(f.Evidence.Facts) > 0 {
			p("   evidence: " + strings.Join(f.Evidence.Facts, ", "))
		}
		if f.Detail != "" {
			p("   detail: " + f.Detail)
		}
		remediationLines(p, f.Remediation)
	}

	h("Attack paths (highest risk first)")
	if len(r.Paths) == 0 {
		p("no attack paths")
	}
	for _, pa := range r.Paths {
		p("risk=" + strconv.Itoa(pa.Risk) + " " + pa.Entry + " to " + pa.Target + " (confidence " + strconv.Itoa(pa.Confidence) + ", " + strconv.Itoa(len(pa.Steps)-1) + " hops)")
	}

	h("Remediation cut candidates (highest leverage first)")
	if len(r.Cuts) == 0 {
		p("no cut candidates")
	}
	for _, c := range r.Cuts {
		p(c.Kind + ": removes " + strconv.Itoa(c.PathsRemoved) + " path(s), risk reduction " + strconv.Itoa(c.RiskReduction) + ", effort " + strconv.Itoa(c.Effort) + ", disruption " + strconv.Itoa(c.Disruption) + ". " + c.Description)
	}

	h("Asset classification")
	if len(r.Classifications) == 0 {
		p("no classified assets")
	}
	for _, c := range r.Classifications {
		p(c.Sensitivity + " (confidence " + strconv.Itoa(c.Confidence) + "): " + c.Entity + " [" + c.Method + "]")
	}

	h("Effective access (ITTCsecID)")
	if r.Identity.Complete {
		p("effective-privilege resolution: complete")
	} else {
		p("effective-privilege resolution: INCOMPLETE (blind spots below); grants are a floor, not exhaustive")
	}
	for _, g := range r.Identity.Gaps {
		p("gap: " + g)
	}
	if len(r.Identity.Grants) == 0 {
		p("no effective-privilege grants resolved")
	}
	for _, gr := range r.Identity.Grants {
		line := gr.Principal + ": " + gr.Privilege + " [" + gr.Effect + "]"
		if len(gr.Via) > 0 {
			line += " (" + strings.Join(gr.Via, "; ") + ")"
		}
		p(line)
	}
	p("dormant privilege: " + r.Identity.DormantStatus)

	h("Changes since the previous scan")
	if r.Changes.ScanID == 0 {
		p("no scan recorded")
	} else if len(r.Changes.Entities) == 0 && len(r.Changes.Edges) == 0 {
		p("no changes recorded (a baseline first scan has no prior state, or nothing changed)")
	}
	for _, ec := range r.Changes.Entities {
		line := ec.Change + ": " + ec.Type + " " + ec.Entity
		if ec.Name != "" {
			line += " (" + ec.Name + ")"
		}
		p(line)
	}
	for _, ec := range r.Changes.Edges {
		p(ec.Change + ": edge " + ec.Source + " -" + ec.Kind + "-> " + ec.Target)
	}

	h("Compliance evidence (ITTCsecProof)")
	p("evidence-coverage map over mapped controls only; status comes from findings, never a certification")
	if len(r.Compliance.Frameworks) == 0 {
		p("no compliance mapping loaded")
	}
	for _, fw := range r.Compliance.Frameworks {
		total := fw.Failed + fw.Passed + fw.NotAssessed
		p(fw.Framework + " (" + fw.Version + ", effective " + fw.EffectiveDate + "): " +
			strconv.Itoa(total) + " mapped controls: " +
			strconv.Itoa(fw.Failed) + " failing, " + strconv.Itoa(fw.Passed) + " passing, " +
			strconv.Itoa(fw.NotAssessed) + " not assessed")
		for _, c := range fw.Controls {
			line := "   " + c.Control + ": " + c.Status
			if len(c.Rules) > 0 {
				line += " (" + strings.Join(c.Rules, ", ") + ")"
			}
			p(line)
		}
	}

	h("Remediation")
	p(r.Remediation)
	return ls
}

// remediationLines renders one finding's remediation: real, doc-verified guidance
// when available, or the honest named-gap statement otherwise. Never placeholder
// guidance.
func remediationLines(p func(string), rem Remediation) {
	if !rem.Available {
		p("   remediation: " + rem.Statement)
		return
	}
	rev := "reversible"
	if !rem.Reversible {
		rev = "NOT reversible"
	}
	p("   remediation (" + rev + ", plan " + rem.PlanHash + "):")
	for _, a := range rem.Actions {
		p("     action [" + a.Provider + "/" + a.Service + "]: " + a.Summary)
		for _, s := range a.PortalSteps {
			p("       portal: " + s)
		}
		for _, c := range a.CLI {
			p("       cli: " + c)
		}
		if a.IaC != "" {
			p("       iac: " + strings.ReplaceAll(a.IaC, "\n", " | "))
		}
	}
	if len(rem.Preconditions) > 0 {
		p("     preconditions: " + strings.Join(rem.Preconditions, " "))
	}
	if len(rem.Privilege) > 0 {
		p("     required privilege: " + strings.Join(rem.Privilege, ", "))
	}
	if len(rem.SideEffects) > 0 {
		p("     side effects: " + strings.Join(rem.SideEffects, " "))
	}
	if len(rem.Verification) > 0 {
		p("     verification: " + strings.Join(rem.Verification, " "))
	}
	if len(rem.Rollback) > 0 {
		p("     rollback: " + strings.Join(rem.Rollback, " "))
	}
}
