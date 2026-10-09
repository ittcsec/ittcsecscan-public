package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
	"github.com/ittcsec/ittcsecscan/internal/version"
	"github.com/ittcsec/ittcsecscan/packs"
)

var fixSpec = commandSpec{
	name:     "fix",
	synopsis: "ittcsecscan fix <plan|simulate> (--tenant <id> | --create) [--provider <list>] [--budget <n>] [--json] [runtime flags]",
	description: "Generate remediation for a tenant's failing findings. fix is plan-only and\n" +
		"read-only: it never changes a cloud.\n\n" +
		"'plan' prints the immutable remediation plan for each failing finding: the\n" +
		"current-state hash, actions with portal, CLI, and IaC steps, preconditions,\n" +
		"required privilege, side effects, verification, reversibility, rollback, and a plan\n" +
		"hash an approval binds to. 'simulate' is a dry run that shows the smallest action\n" +
		"that would be applied and the guards that protect it, and confirms nothing is\n" +
		"written.\n\n" +
		"A finding whose type has no verified remediation yet is shown as an honest named\n" +
		"gap, never fabricated guidance. Write execution is compiled out of this binary; it\n" +
		"requires a separate build and a dedicated remediation credential profile, so fix\n" +
		"can never modify a resource.",
}

// fixEntry pairs a generated plan with the native id of the affected resource, for
// display. The plan itself carries only the tenant-scoped stable id.
type fixEntry struct {
	Plan   remediate.GeneratedPlan
	Native string
	Risk   int
}

func runFix(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		return exitcode.Errorf(exitcode.Usage, "fix: expected a subcommand: plan or simulate (run 'ittcsecscan help fix')")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeCommandHelp(inv.out, newFlagSet(fixSpec.name), fixSpec)
		return nil
	}
	sub := args[0]
	if sub != "plan" && sub != "simulate" {
		return exitcode.Errorf(exitcode.Usage, "fix: unknown subcommand %q (want plan or simulate)", sub)
	}

	fs := newFlagSet(fixSpec.name + " " + sub)
	var rf runtimeFlags
	rf.register(fs)
	var sf scanFlags
	fs.StringVar(&sf.tenant, "tenant", "", "the `id` of an existing tenant")
	fs.BoolVar(&sf.create, "create", false, "create a new tenant and scan it (prints the new id)")
	fs.StringVar(&sf.provider, "provider", "", "comma-separated `list` of providers (default: all with collectors)")
	fs.Int64Var(&sf.budget, "budget", 0, "max provider collection `calls`, 0 = unlimited")
	fs.BoolVar(&sf.asJSON, "json", false, "print JSON")
	spec := commandSpec{name: "fix " + sub, synopsis: fixSpec.synopsis, description: fixSpec.description}
	if done, err := parse(fs, inv, spec, args[1:]); done {
		return err
	}

	entries, id, err := generateFixPlans(ctx, inv, rf, sf)
	if err != nil {
		return err
	}
	if sub == "plan" {
		return writeFixPlans(inv.out, sf.asJSON, id, entries)
	}
	return writeFixSimulation(inv.out, sf.asJSON, id, entries)
}

// generateFixPlans runs the same read-only collect and analyze pipeline as scan,
// then returns the remediation plan for every failing finding. It writes nothing to
// any cloud; plan generation is deterministic and offline.
func generateFixPlans(ctx context.Context, inv *invocation, rf runtimeFlags, sf scanFlags) ([]fixEntry, store.TenantID, error) {
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
	var entries []fixEntry
	for _, p := range rep.Providers {
		if p.AuthError != nil {
			continue
		}
		res, err := pipeline.AnalyzeScan(p.Scan, keyer, p.Provider, overrides, ruleset)
		if err != nil {
			return nil, id, err
		}
		for _, f := range res.RankedFindings {
			if f.Plan != nil {
				entries = append(entries, fixEntry{Plan: *f.Plan, Native: f.Native, Risk: f.Finding.Risk})
			}
		}
	}
	return entries, id, nil
}

func writeFixPlans(w io.Writer, asJSON bool, id store.TenantID, entries []fixEntry) error {
	if asJSON {
		return writeJSON(w, fixJSON(id, entries, "plan"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Remediation plans for tenant %s (plan-only; no changes are made)\n", id)
	if len(entries) == 0 {
		b.WriteString("no failing findings; nothing to remediate\n")
		return writeText(w, b.String())
	}
	for _, e := range entries {
		p := e.Plan
		fmt.Fprintf(&b, "\n%s on %s (risk %d)\n", p.Finding.RuleID, e.Native, e.Risk)
		fmt.Fprintf(&b, "  current-state hash: %s\n  plan hash: %s\n", p.CurrentStateHash, p.PlanHash)
		if !p.Available {
			fmt.Fprintf(&b, "  remediation: gap: %s\n", p.GapReason)
			continue
		}
		rev := "reversible"
		if !p.Reversible {
			rev = "NOT reversible"
		}
		fmt.Fprintf(&b, "  %s\n", rev)
		for _, a := range p.Actions {
			fmt.Fprintf(&b, "  action [%s/%s]: %s\n", a.Provider, a.Service, a.Summary)
			for _, s := range a.PortalSteps {
				fmt.Fprintf(&b, "    portal: %s\n", s)
			}
			for _, c := range a.CLI {
				fmt.Fprintf(&b, "    cli: %s\n", c)
			}
			if a.IaC != "" {
				fmt.Fprintf(&b, "    iac:\n%s\n", indent(a.IaC, "      "))
			}
		}
		writeList(&b, "preconditions", p.Preconditions)
		writeList(&b, "required privilege", p.RequiredPrivilege)
		writeList(&b, "side effects", p.SideEffects)
		writeList(&b, "verification", p.Verification)
		writeList(&b, "rollback", p.Rollback)
	}
	return writeText(w, b.String())
}

func writeFixSimulation(w io.Writer, asJSON bool, id store.TenantID, entries []fixEntry) error {
	if asJSON {
		return writeJSON(w, fixJSON(id, entries, "simulate"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Remediation simulation for tenant %s (DRY RUN; no changes are made)\n", id)
	fmt.Fprintf(&b, "Write execution is %s in this build; applying requires a separate build and a dedicated remediation credential profile.\n", enabledWord())
	if len(entries) == 0 {
		b.WriteString("no failing findings; nothing to simulate\n")
		return writeText(w, b.String())
	}
	for _, e := range entries {
		p := e.Plan
		fmt.Fprintf(&b, "\n%s on %s (risk %d)\n", p.Finding.RuleID, e.Native, e.Risk)
		if !p.Available {
			fmt.Fprintf(&b, "  would do nothing: %s\n", p.GapReason)
			continue
		}
		a := p.Actions[0] // the smallest action the executor would apply first
		fmt.Fprintf(&b, "  would apply the smallest action [%s/%s]: %s\n", a.Provider, a.Service, a.Summary)
		if len(a.CLI) > 0 {
			fmt.Fprintf(&b, "  equivalent command: %s\n", a.CLI[0])
		}
		fmt.Fprintf(&b, "  required credential profile: remediation (never the read-only scanning profile)\n")
		fmt.Fprintf(&b, "  approval must match plan hash: %s\n", p.PlanHash)
		fmt.Fprintf(&b, "  drift guard: apply is refused unless current-state hash still equals %s\n", p.CurrentStateHash)
	}
	b.WriteString("\nDRY RUN complete: no resource was read for write and nothing was changed.\n")
	return writeText(w, b.String())
}

// enabledWord reports whether provider-write execution is available in this binary.
// fix is plan-only and never links the executor, so a fix-capable binary is always a
// build in which writing is disabled; applying requires a separate build (the
// remediation build tag) and a dedicated remediation credential profile.
func enabledWord() string {
	return "disabled"
}

type fixPlanJSON struct {
	Tenant string         `json:"tenant"`
	Mode   string         `json:"mode"`
	Plans  []fixEntryJSON `json:"plans"`
}

type fixEntryJSON struct {
	Native string                  `json:"native_id"`
	Risk   int                     `json:"risk"`
	Plan   remediate.GeneratedPlan `json:"plan"`
}

func fixJSON(id store.TenantID, entries []fixEntry, mode string) fixPlanJSON {
	out := fixPlanJSON{Tenant: id.String(), Mode: mode, Plans: make([]fixEntryJSON, 0, len(entries))}
	for _, e := range entries {
		out.Plans = append(out.Plans, fixEntryJSON{Native: redact.String(e.Native), Risk: e.Risk, Plan: e.Plan})
	}
	return out
}

func writeList(b *strings.Builder, label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s: %s\n", label, strings.Join(items, " "))
}

func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = pad + ln
	}
	return strings.Join(lines, "\n")
}

// writeText redacts secrets and neutralizes terminal control sequences before
// writing, the same discipline the other human-readable command outputs use.
func writeText(w io.Writer, s string) error {
	_, err := io.WriteString(w, termsafe.String(redact.String(s)))
	return err
}
