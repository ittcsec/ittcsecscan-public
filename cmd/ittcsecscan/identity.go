package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/graph"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/report"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/version"
	"github.com/ittcsec/ittcsecscan/packs"
)

var identitySpec = commandSpec{
	name:     "identity",
	synopsis: "ittcsecscan identity (--tenant <id> | --create) [--provider <list>] [--budget <n>] [--json] [runtime flags]",
	description: "Surface ITTCsecID: who effectively holds what privilege, with deny-override\n" +
		"semantics (ADR-0022), resolved read-only from the collected graph. It reports the\n" +
		"same effective-privilege resolution the attack-path engine consumes; it computes no\n" +
		"new facts. Deny overrides allow: a grant shows effect 'deny' when a permission\n" +
		"boundary cap or an explicit deny removed it.\n\n" +
		"Dormant-privilege detection is shown as an honest named gap: no last-used or\n" +
		"credential-age signal is collected (deferred, ADR-0021 section 7), so it is reported\n" +
		"as a gap, never inferred from a weaker proxy.",
}

func runIdentity(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(identitySpec.name)
	var rf runtimeFlags
	rf.register(fs)
	var sf scanFlags
	fs.StringVar(&sf.tenant, "tenant", "", "the `id` of an existing tenant")
	fs.BoolVar(&sf.create, "create", false, "create a new tenant and scan it (prints the new id)")
	fs.StringVar(&sf.provider, "provider", "", "comma-separated `list` of providers (default: all with collectors)")
	fs.Int64Var(&sf.budget, "budget", 0, "max provider collection `calls`, 0 = unlimited")
	fs.BoolVar(&sf.asJSON, "json", false, "print JSON")
	if done, err := parse(fs, inv, identitySpec, args); done {
		return err
	}
	identity, id, err := resolveIdentity(ctx, inv, rf, sf)
	if err != nil {
		return err
	}
	return writeIdentity(inv.out, sf.asJSON, id, identity)
}

// resolveIdentity runs the same read-only collect and analyze pipeline as scan, then
// aggregates the effective-privilege resolution across providers. It writes nothing.
func resolveIdentity(ctx context.Context, inv *invocation, rf runtimeFlags, sf scanFlags) (graph.EffectiveResult, store.TenantID, error) {
	sources, err := selectSources(sf.provider, inv.lookupEnv)
	if err != nil {
		return graph.EffectiveResult{}, store.TenantID{}, err
	}
	intent, err := resolveTenantIntent(sf)
	if err != nil {
		return graph.EffectiveResult{}, store.TenantID{}, err
	}
	st, err := openStore(inv, rf)
	if err != nil {
		return graph.EffectiveResult{}, store.TenantID{}, err
	}
	defer func() { _ = st.Close() }()

	tn, id, release, err := intent.open(ctx, st)
	if err != nil {
		return graph.EffectiveResult{}, store.TenantID{}, err
	}
	defer release()

	rep, err := scan.Run(ctx, version.Get().Version, sources, scanBudget(sf.budget), tn)
	if err != nil {
		return graph.EffectiveResult{}, id, err
	}
	trusted, err := pack.TrustedBuiltinKeys(packs.AllowedSigners())
	if err != nil {
		return graph.EffectiveResult{}, id, err
	}
	ruleset, err := pack.LoadBuiltinAll(packs.FS, trusted)
	if err != nil {
		return graph.EffectiveResult{}, id, err
	}
	overrides, err := tn.CriticalityOverrides(ctx)
	if err != nil {
		return graph.EffectiveResult{}, id, err
	}
	keyer := tenantKeyer{tn: tn}
	identity := graph.EffectiveResult{Complete: true}
	for _, p := range rep.Providers {
		if p.AuthError != nil {
			continue // a provider that did not authenticate resolved no privilege
		}
		res, err := pipeline.AnalyzeScan(p.Scan, keyer, p.Provider, overrides, ruleset)
		if err != nil {
			return graph.EffectiveResult{}, id, err
		}
		identity.Grants = append(identity.Grants, res.Identity.Grants...)
		if !res.Identity.Complete {
			identity.Complete = false
		}
		identity.Gaps = append(identity.Gaps, res.Identity.Gaps...)
	}
	return identity, id, nil
}

// sortedGrants returns the grants ordered by principal then privilege, for deterministic
// output.
func sortedGrants(grants []model.Permission) []model.Permission {
	out := append([]model.Permission(nil), grants...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Principal != out[j].Principal {
			return out[i].Principal < out[j].Principal
		}
		return out[i].Action < out[j].Action
	})
	return out
}

func writeIdentity(w io.Writer, asJSON bool, id store.TenantID, idn graph.EffectiveResult) error {
	if asJSON {
		return writeJSON(w, identityJSON(id, idn))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ITTCsecID: effective access for tenant %s (read-only; deny overrides allow)\n", id)
	if idn.Complete {
		b.WriteString("effective-privilege resolution: complete\n")
	} else {
		b.WriteString("effective-privilege resolution: INCOMPLETE (blind spots below); grants are a floor, not exhaustive\n")
	}
	for _, g := range idn.Gaps {
		fmt.Fprintf(&b, "  gap: %s\n", g)
	}
	if len(idn.Grants) == 0 {
		b.WriteString("  no effective-privilege grants resolved\n")
	}
	for _, gr := range sortedGrants(idn.Grants) {
		fmt.Fprintf(&b, "  %s: %s [%s]", gr.Principal, gr.Action, gr.Effect)
		if gr.InheritedFrom != "" {
			fmt.Fprintf(&b, " (inherited from %s)", gr.InheritedFrom)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "dormant privilege: %s\n", report.DormantGapStatus)
	return writeText(w, b.String())
}

type identityOut struct {
	Tenant        string             `json:"tenant"`
	Complete      bool               `json:"complete"`
	Gaps          []string           `json:"gaps"`
	Grants        []identityGrantOut `json:"grants"`
	DormantStatus string             `json:"dormant_status"`
}

type identityGrantOut struct {
	Principal     string `json:"principal"`
	Privilege     string `json:"privilege"`
	Effect        string `json:"effect"`
	InheritedFrom string `json:"inherited_from,omitempty"`
}

func identityJSON(id store.TenantID, idn graph.EffectiveResult) identityOut {
	out := identityOut{
		Tenant: id.String(), Complete: idn.Complete,
		Gaps: make([]string, 0, len(idn.Gaps)), Grants: make([]identityGrantOut, 0, len(idn.Grants)),
		DormantStatus: report.DormantGapStatus,
	}
	for _, g := range idn.Gaps {
		out.Gaps = append(out.Gaps, redact.String(g))
	}
	for _, gr := range sortedGrants(idn.Grants) {
		out.Grants = append(out.Grants, identityGrantOut{
			Principal:     redact.String(string(gr.Principal)),
			Privilege:     redact.String(gr.Action),
			Effect:        string(gr.Effect),
			InheritedFrom: redact.String(string(gr.InheritedFrom)),
		})
	}
	return out
}
