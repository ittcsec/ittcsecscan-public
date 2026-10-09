package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
)

var authSpec = commandSpec{
	name:     "auth",
	synopsis: "ittcsecscan auth plan [flags]",
	description: "Inspect how ittcsecscan authenticates to a cloud provider. Read-only:\n" +
		"it never creates, stores, or retrieves a credential.\n\n" +
		"  plan   Resolve the caller's identity for each provider under a\n" +
		"         least-privilege profile and report it. Exits 7 (auth-failed) if\n" +
		"         any requested provider cannot authenticate; an unknown or denied\n" +
		"         result is never reported as success.",
}

var authPlanSpec = commandSpec{
	name:     "auth plan",
	synopsis: "ittcsecscan auth plan [--provider aws|azure|gcp] [--profile discovery]",
	description: "Resolve the caller's identity for each requested provider under a\n" +
		"least-privilege profile (default discovery) and report it. No credential\n" +
		"material is read, stored, or logged. If any requested provider cannot\n" +
		"authenticate, the command exits 7 (auth-failed).",
}

// authPlanFlags registers the plan flags on fs.
func authPlanFlags(fs *flag.FlagSet) (provider, profile *string) {
	provider = fs.String("provider", "", "limit to one provider (aws, azure, or gcp); default all")
	profile = fs.String("profile", string(auth.Discovery), "credential `profile`: discovery, deep-evidence, or remediation")
	return provider, profile
}

func runAuth(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		writeCommandHelp(inv.out, authHelpFlags(), authSpec)
		return exitcode.Errorf(exitcode.Usage, "auth: a subcommand is required (plan)")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeCommandHelp(inv.out, authHelpFlags(), authSpec)
		return nil
	case "plan":
		return runAuthPlan(ctx, inv, args[1:])
	default:
		return exitcode.Errorf(exitcode.Usage, "auth: unknown subcommand %q (plan)", args[0])
	}
}

// authHelpFlags returns a flag set carrying the plan flags, so auth help lists
// them.
func authHelpFlags() *flag.FlagSet {
	fs := newFlagSet(authSpec.name)
	authPlanFlags(fs)
	return fs
}

func runAuthPlan(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(authPlanSpec.name)
	providerFlag, profileFlag := authPlanFlags(fs)
	if done, err := parse(fs, inv, authPlanSpec, args); done {
		return err
	}

	profile := auth.Profile(*profileFlag)
	if !profile.Valid() {
		return exitcode.Errorf(exitcode.Usage, "auth plan: unknown profile %q (discovery, deep-evidence, or remediation)", *profileFlag)
	}
	providers, err := selectProviders(*providerFlag)
	if err != nil {
		return err
	}

	failed := 0
	for _, p := range providers {
		// The operator's interrupt stops the command as an interrupt, not an
		// auth failure.
		if err := ctx.Err(); err != nil {
			return err
		}
		id, rerr := inv.resolver.Resolve(ctx, p, profile)
		if rerr != nil {
			failed++
			_, _ = fmt.Fprintf(inv.out, "%-6s %-12s auth-failed  %s\n", p, profile, safeField(rerr.Error()))
			continue
		}
		_, _ = fmt.Fprintf(inv.out, "%-6s %-12s resolved     account=%s principal=%s\n",
			p, profile, safeField(id.Account), safeField(id.Principal))
		if note := resolvedNote(p, id); note != "" {
			_, _ = fmt.Fprintf(inv.out, "%-6s %-12s %s\n", "", "", note)
		}
	}
	if failed > 0 {
		// Any single provider failing forces auth-failed: the CLI never reports
		// success it did not fully establish.
		return exitcode.Wrap(exitcode.AuthFailed,
			fmt.Errorf("%d of %d providers could not authenticate", failed, len(providers)))
	}
	return nil
}

// selectProviders resolves the --provider flag to the providers to plan. An
// empty flag means all providers.
func selectProviders(flag string) ([]model.Provider, error) {
	if flag == "" {
		return model.Providers, nil
	}
	p := model.Provider(flag)
	if !p.Valid() {
		return nil, exitcode.Errorf(exitcode.Usage, "auth plan: unknown provider %q (aws, azure, or gcp)", flag)
	}
	return []model.Provider{p}, nil
}

// resolvedNote returns a clarification printed under a resolved identity when a
// field's meaning is provider-specific and could be misread. For Azure the
// principal is the authenticated tenant, not a specific caller. For GCP an empty
// account means the credential has no associated default project; the principal
// is still the authenticated identity.
func resolvedNote(p model.Provider, id auth.Identity) string {
	switch p {
	case model.Azure:
		return "note: for Azure, principal is the authenticated tenant, not a specific user or service principal; identifying the calling identity needs more permission (the collectors)"
	case model.GCP:
		if id.Account == "" {
			return "note: for GCP, an empty account means the credential has no associated default project; the principal above is still the authenticated identity"
		}
	}
	return ""
}

// safeField makes a provider-derived string safe for the command's own output:
// secrets scrubbed, terminal control sequences neutralised. Identity fields are
// non-secret by contract; this is defence in depth at the CLI boundary, matching
// how run() treats error text.
func safeField(s string) string {
	return termsafe.String(redact.String(s))
}
