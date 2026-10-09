package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/compliance"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/version"
	"github.com/ittcsec/ittcsecscan/packs"
)

var complianceSpec = commandSpec{
	name:     "compliance",
	synopsis: "ittcsecscan compliance (--tenant <id> | --create) [--provider <list>] [--budget <n>] [--json] [runtime flags]",
	description: "Surface ITTCsecProof: map real findings to the controls of common regulatory and\n" +
		"audit frameworks (NIS2, ISO 27001, GDPR, SOC 2, DORA, CRA). Status is derived only\n" +
		"from findings: fail (a rule mapped to the control produced a failing finding), pass\n" +
		"(every mapped rule that produced a conclusive finding passed, with none unknown), or\n" +
		"not assessed (no finding backs it, or its evidence was unknown or not applicable).\n\n" +
		"This is an evidence-coverage map over the controls the mapping references, never a\n" +
		"certification and never a claim that the tenant is compliant with a framework. For\n" +
		"the current rule set, most mapped controls are not assessed.",
}

func runCompliance(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(complianceSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	var sf scanFlags
	fs.StringVar(&sf.tenant, "tenant", "", "the `id` of an existing tenant")
	fs.BoolVar(&sf.create, "create", false, "create a new tenant and scan it (prints the new id)")
	fs.StringVar(&sf.provider, "provider", "", "comma-separated `list` of providers (default: all with collectors)")
	fs.Int64Var(&sf.budget, "budget", 0, "max provider collection `calls`, 0 = unlimited")
	fs.BoolVar(&sf.asJSON, "json", false, "print JSON")
	if done, err := parse(fs, inv, complianceSpec, args); done {
		return err
	}
	findings, id, err := resolveComplianceFindings(ctx, inv, rf, sf)
	if err != nil {
		return err
	}
	mapping, err := compliance.Load(packs.ComplianceMapping())
	if err != nil {
		return err
	}
	res := compliance.Evaluate(mapping, adaptFindings(findings))
	return writeCompliance(inv.out, sf.asJSON, id, res)
}

// resolveComplianceFindings runs the same read-only collect and analyze pipeline as scan,
// then aggregates the ranked findings across providers. It writes nothing.
func resolveComplianceFindings(ctx context.Context, inv *invocation, rf runtimeFlags, sf scanFlags) ([]pipeline.RankedFinding, store.TenantID, error) {
	sources, err := selectSources(sf.provider, inv.lookupEnv)
	if err != nil {
		return nil, store.TenantID{}, err
	}
	intent, err := resolveTenantIntent(sf)
	if err != nil {
		return nil, store.TenantID{}, err
	}
	st, err := openStore(inv, rf)
	if err != nil {
		return nil, store.TenantID{}, err
	}
	defer func() { _ = st.Close() }()

	tn, id, release, err := intent.open(ctx, st)
	if err != nil {
		return nil, store.TenantID{}, err
	}
	defer release()

	rep, err := scan.Run(ctx, version.Get().Version, sources, scanBudget(sf.budget), tn)
	if err != nil {
		return nil, id, err
	}
	trusted, err := pack.TrustedBuiltinKeys(packs.AllowedSigners())
	if err != nil {
		return nil, id, err
	}
	ruleset, err := pack.LoadBuiltinAll(packs.FS, trusted)
	if err != nil {
		return nil, id, err
	}
	overrides, err := tn.CriticalityOverrides(ctx)
	if err != nil {
		return nil, id, err
	}
	keyer := tenantKeyer{tn: tn}
	var findings []pipeline.RankedFinding
	for _, p := range rep.Providers {
		if p.AuthError != nil {
			continue // a provider that did not authenticate produced no findings
		}
		res, err := pipeline.AnalyzeScan(p.Scan, keyer, p.Provider, overrides, ruleset)
		if err != nil {
			return nil, id, err
		}
		findings = append(findings, res.RankedFindings...)
	}
	return findings, id, nil
}

// adaptFindings maps the engine's ranked findings onto the minimal view the compliance
// status computation needs: a rule id and its outcome.
func adaptFindings(findings []pipeline.RankedFinding) []compliance.Finding {
	out := make([]compliance.Finding, 0, len(findings))
	for _, rf := range findings {
		out = append(out, compliance.Finding{RuleID: rf.Finding.Rule.RuleID, State: rf.Finding.State})
	}
	return out
}

func writeCompliance(w io.Writer, asJSON bool, id store.TenantID, res compliance.Result) error {
	if asJSON {
		return writeJSON(w, complianceJSON(id, res))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ITTCsecProof: compliance evidence for tenant %s\n", id)
	b.WriteString("evidence-coverage map over mapped controls only; status comes from findings, never a certification\n")
	for _, fw := range res.Frameworks {
		total := fw.Failed + fw.Passed + fw.NotAssessed
		fmt.Fprintf(&b, "%s (%s, effective %s): %d mapped controls: %d failing, %d passing, %d not assessed\n",
			fw.Framework, fw.Version, fw.EffectiveDate, total, fw.Failed, fw.Passed, fw.NotAssessed)
		for _, c := range fw.Controls {
			line := "  " + c.Control + ": " + string(c.Status)
			if len(c.Rules) > 0 {
				line += " (" + strings.Join(c.Rules, ", ") + ")"
			}
			b.WriteString(line + "\n")
		}
	}
	return writeText(w, b.String())
}

type complianceOut struct {
	Tenant     string         `json:"tenant"`
	Frameworks []frameworkOut `json:"frameworks"`
	Note       string         `json:"note"`
}

type frameworkOut struct {
	Framework     string       `json:"framework"`
	Version       string       `json:"version"`
	EffectiveDate string       `json:"effective_date"`
	Failed        int          `json:"failed"`
	Passed        int          `json:"passed"`
	NotAssessed   int          `json:"not_assessed"`
	Controls      []controlOut `json:"controls"`
}

type controlOut struct {
	Control string   `json:"control"`
	Status  string   `json:"status"`
	Rules   []string `json:"rules,omitempty"`
}

func complianceJSON(id store.TenantID, res compliance.Result) complianceOut {
	out := complianceOut{
		Tenant:     id.String(),
		Frameworks: make([]frameworkOut, 0, len(res.Frameworks)),
		Note:       "evidence-coverage map over mapped controls only; status is derived only from findings and is never a certification",
	}
	for _, fw := range res.Frameworks {
		fo := frameworkOut{
			Framework: redact.String(fw.Framework), Version: redact.String(fw.Version), EffectiveDate: redact.String(fw.EffectiveDate),
			Failed: fw.Failed, Passed: fw.Passed, NotAssessed: fw.NotAssessed,
			Controls: make([]controlOut, 0, len(fw.Controls)),
		}
		for _, c := range fw.Controls {
			fo.Controls = append(fo.Controls, controlOut{Control: redact.String(c.Control), Status: string(c.Status), Rules: c.Rules})
		}
		out.Frameworks = append(out.Frameworks, fo)
	}
	return out
}
