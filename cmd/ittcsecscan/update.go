package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/app"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/update"
)

var updateSpec = commandSpec{
	name:     "update",
	synopsis: "ittcsecscan update <check|status|offline|rollback> [flags] [runtime flags]",
	description: "Update components (binary, detection packs, schemas, and later collectors,\n" +
		"remediation packs, compliance mappings, threat intelligence) from signed metadata,\n" +
		"applying The Update Framework principles: updates come only from trusted, signed\n" +
		"metadata anchored to a pinned root, never a mutable URL, and rollback, freeze,\n" +
		"mix-and-match, and repository compromise are refused (ADR-0030).\n\n" +
		"Subcommands:\n" +
		"  check    Verify metadata and report available updates (installs nothing).\n" +
		"  status   Show installed component versions and the last-known-good.\n" +
		"  offline  Verify and install from a local signed bundle, with no network.\n" +
		"  rollback Restore a component's retained last-known-good version.\n\n" +
		"Update checks transmit no inventory, no credentials, and not even installed\n" +
		"versions: only a bare metadata GET with a minimal, anonymous User-Agent.",
}

func runUpdate(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		return exitcode.Errorf(exitcode.Usage, "update: expected a subcommand: check, status, offline, or rollback")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeCommandHelp(inv.out, newFlagSet(updateSpec.name), updateSpec)
		return nil
	case "check":
		return runUpdateCheck(ctx, inv, args[1:])
	case "status":
		return runUpdateStatus(ctx, inv, args[1:])
	case "offline":
		return runUpdateOffline(ctx, inv, args[1:])
	case "rollback":
		return runUpdateRollback(ctx, inv, args[1:])
	default:
		return exitcode.Errorf(exitcode.Usage, "update: unknown subcommand %q (want check, status, offline, or rollback)", args[0])
	}
}

// updateStore opens the install store under the configured data directory.
func updateStore(inv *invocation, rf runtimeFlags) (*update.Store, error) {
	a := app.NewLenient(app.Options{Overrides: rf.overrides(), LookupEnv: inv.lookupEnv, Stderr: inv.err})
	if a.Config.DataDir == "" {
		return nil, exitcode.Errorf(exitcode.Usage, "update: no data directory configured; set --data-dir or data_dir")
	}
	return update.NewStore(filepath.Join(a.Config.DataDir, "updates"))
}

// loadClient reads the pinned trust root and anchors an update client to it.
func loadClient(rootPath string) (*update.Client, error) {
	if rootPath == "" {
		return nil, exitcode.Errorf(exitcode.Usage, "update: a pinned trust root is required (--root); no production root is shipped yet (UP-7)")
	}
	raw, err := os.ReadFile(rootPath) //nolint:gosec // G304: operator-supplied trust-root path
	if err != nil {
		return nil, exitcode.Wrap(exitcode.Usage, err)
	}
	c, err := update.NewClient(raw, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runUpdateStatus(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("update status")
	var rf runtimeFlags
	rf.register(fs)
	spec := commandSpec{name: "update status", synopsis: "ittcsecscan update status [runtime flags]", description: updateSpec.description}
	if done, err := parse(fs, inv, spec, args); done {
		return err
	}
	st, err := updateStore(inv, rf)
	if err != nil {
		return err
	}
	installed, err := st.Installed()
	if err != nil {
		return err
	}
	var b strings.Builder
	if len(installed) == 0 {
		b.WriteString("no components installed by the updater\n")
	} else {
		b.WriteString("installed components:\n")
		names := make([]string, 0, len(installed))
		for n := range installed {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			i := installed[n]
			line := fmt.Sprintf("  %s %s", i.Component, i.Version)
			if i.HasPrevious {
				line += fmt.Sprintf(" (last-known-good: %s)", i.PreviousVersion)
			}
			b.WriteString(line + "\n")
		}
	}
	return writeText(inv.out, b.String())
}

func runUpdateCheck(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("update check")
	var rf runtimeFlags
	rf.register(fs)
	root := fs.String("root", "", "path to the pinned trust-root metadata `file`")
	repo := fs.String("repo", "", "base `URL` of the HTTPS update repository")
	component := fs.String("component", "", "restrict to a single component `name`")
	channel := fs.String("channel", "", "restrict to a release `channel`")
	spec := commandSpec{name: "update check", synopsis: "ittcsecscan update check --root <file> --repo <url> [--component <name>] [--channel <name>]", description: updateSpec.description}
	if done, err := parse(fs, inv, spec, args); done {
		return err
	}
	if *repo == "" {
		return exitcode.Errorf(exitcode.Usage, "update check: --repo is required")
	}
	c, err := loadClient(*root)
	if err != nil {
		return err
	}
	fetcher, err := update.NewHTTPFetcher(*repo)
	if err != nil {
		return err
	}
	st, err := updateStore(inv, rf)
	if err != nil {
		return err
	}
	return reportAvailable(inv.out, c, fetcher, st, *component, *channel, false)
}

func runUpdateOffline(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("update offline")
	var rf runtimeFlags
	rf.register(fs)
	root := fs.String("root", "", "path to the pinned trust-root metadata `file`")
	component := fs.String("component", "", "install only this component `name`")
	channel := fs.String("channel", "", "restrict to a release `channel`")
	spec := commandSpec{name: "update offline", synopsis: "ittcsecscan update offline <bundle-dir> --root <file> [--component <name>]", description: updateSpec.description}
	// Accept the bundle directory before or after the flags: Go's flag package stops
	// at the first positional, so pull a leading positional out before parsing.
	var bundle string
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		bundle, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return parseErr(inv, spec, err)
	}
	if bundle == "" {
		switch fs.NArg() {
		case 1:
			bundle = fs.Arg(0)
		case 0:
			return exitcode.Errorf(exitcode.Usage, "update offline: expected exactly one bundle directory")
		default:
			return exitcode.Errorf(exitcode.Usage, "update offline: expected exactly one bundle directory")
		}
	} else if fs.NArg() != 0 {
		return exitcode.Errorf(exitcode.Usage, "update offline: unexpected argument %q", fs.Arg(0))
	}
	c, err := loadClient(*root)
	if err != nil {
		return err
	}
	fetcher := update.NewDirFetcher(bundle)
	st, err := updateStore(inv, rf)
	if err != nil {
		return err
	}
	return reportAvailable(inv.out, c, fetcher, st, *component, *channel, true)
}

func runUpdateRollback(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet("update rollback")
	var rf runtimeFlags
	rf.register(fs)
	component := fs.String("component", "", "component `name` to roll back")
	spec := commandSpec{name: "update rollback", synopsis: "ittcsecscan update rollback --component <name> [runtime flags]", description: updateSpec.description}
	if done, err := parse(fs, inv, spec, args); done {
		return err
	}
	if *component == "" {
		return exitcode.Errorf(exitcode.Usage, "update rollback: --component is required")
	}
	st, err := updateStore(inv, rf)
	if err != nil {
		return err
	}
	info, err := st.Rollback(*component)
	if err != nil {
		return exitcode.Wrap(exitcode.Usage, err)
	}
	return writeText(inv.out, fmt.Sprintf("rolled back %s to %s\n", info.Component, info.Version))
}

// reportAvailable verifies the chain and reports each target's component and version
// against what is installed. When install is true (offline), it installs verified
// targets that are new or changed; otherwise (check) it only reports.
func reportAvailable(w io.Writer, c *update.Client, f update.Fetcher, st *update.Store, component, channel string, install bool) error {
	tgts, err := c.VerifyChain(f)
	if err != nil {
		return err
	}
	installed, err := st.Installed()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(tgts.Targets))
	for n := range tgts.Targets {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	action := "available"
	if install {
		action = "installed"
	}
	count := 0
	for _, name := range names {
		tgt := tgts.Targets[name]
		if component != "" && tgt.Custom.Component != component {
			continue
		}
		if channel != "" && tgt.Custom.Channel != channel {
			continue
		}
		cur, have := installed[tgt.Custom.Component]
		if have && cur.Version == tgt.Custom.Version {
			continue // already current
		}
		count++
		if install {
			_, data, err := c.FetchAndVerifyTarget(f, tgts, name)
			if err != nil {
				return err
			}
			if err := st.Install(tgt.Custom.Component, tgt.Custom.Version, data); err != nil {
				return err
			}
		}
		from := "not installed"
		if have {
			from = cur.Version
		}
		fmt.Fprintf(&b, "  %s: %s -> %s (%s, channel %s)\n", tgt.Custom.Component, from, tgt.Custom.Version, action, tgt.Custom.Channel)
	}
	if count == 0 {
		b.WriteString("everything is up to date\n")
	} else {
		header := fmt.Sprintf("%d update(s) %s:\n", count, action)
		return writeText(w, header+b.String())
	}
	return writeText(w, b.String())
}

// parseErr renders a flag parse error consistently with parse().
func parseErr(inv *invocation, spec commandSpec, err error) error {
	if err.Error() == "flag: help requested" {
		writeCommandHelp(inv.out, newFlagSet(spec.name), spec)
		return nil
	}
	return exitcode.Errorf(exitcode.Usage, "%s: %v", spec.name, err)
}
