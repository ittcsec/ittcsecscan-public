package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/app"
	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/doctor"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/termsafe"
	"github.com/ittcsec/ittcsecscan/internal/version"
)

// streams are the output destinations. Command results go to out; logs and
// errors go to err, so out stays machine-readable.
type streams struct {
	out io.Writer
	err io.Writer
}

// secretReader reads one secret (a passphrase) with the prompt shown but the
// input not echoed. It is injected so commands stay testable: main wires it to
// the terminal, tests supply canned input.
type secretReader func(prompt string) ([]byte, error)

type invocation struct {
	streams
	lookupEnv  config.LookupEnv
	readSecret secretReader
	resolver   *auth.Registry
}

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, inv *invocation, args []string) error
}

// commands lists every command, sorted by name.
func commands() []command {
	return []command{
		{name: "auth", summary: "Inspect how ittcsecscan authenticates to a provider (read-only)", run: runAuth},
		{name: "classify", summary: "Manage audited business-criticality overrides for a tenant", run: runClassify},
		{name: "compliance", summary: "Surface ITTCsecProof: map findings to framework controls, evidence only (read-only)", run: runCompliance},
		{name: "diff", summary: "Show what changed between a tenant's scans (read-only)", run: runDiff},
		{name: "doctor", summary: "Check the local environment and configuration (read-only)", run: runDoctor},
		{name: "fix", summary: "Generate plan-only remediation for a tenant's findings (read-only)", run: runFix},
		{name: "help", summary: "Show help for ittcsecscan or one of its commands", run: runHelp},
		{name: "identity", summary: "Surface ITTCsecID: effective privilege and deny-override view for a tenant (read-only)", run: runIdentity},
		{name: "keys", summary: "Create and check the operator master key", run: runKeys},
		{name: "scan", summary: "Collect a tenant's cloud graph into a sealed, change-tracked scan", run: runScan},
		{name: "trust", summary: "Verify or prepare a signed, independently verifiable trust report (ITTCsecProof, read-only)", run: runTrust},
		{name: "update", summary: "Update components from signed metadata (TUF principles, read-only check)", run: runUpdate},
		{name: "verify-trust", summary: "Verify pack and release signatures in process, fail-closed (read-only)", run: runVerifyTrust},
		{name: "version", summary: "Print build identity", run: runVersion},
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// run executes one CLI invocation and returns its exit code. It is the whole
// program minus process wiring.
func run(ctx context.Context, args []string, s streams, lookupEnv config.LookupEnv, readSecret secretReader, resolver *auth.Registry) exitcode.Code {
	inv := &invocation{streams: s, lookupEnv: lookupEnv, readSecret: readSecret, resolver: resolver}
	err := dispatch(ctx, inv, args)
	code := exitcode.From(err)
	switch {
	case err == nil:
	case code == exitcode.Interrupted:
		_, _ = fmt.Fprintln(s.err, "ittcsecscan: interrupted")
	default:
		// Errors can quote configuration values, paths, or provider messages:
		// redact secrets, then neutralise terminal control sequences.
		_, _ = fmt.Fprintf(s.err, "ittcsecscan: %s\n", termsafe.String(redact.String(err.Error())))
	}
	return code
}

func dispatch(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		writeUsage(inv.err)
		return exitcode.Errorf(exitcode.Usage, "no command given")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeUsage(inv.out)
		return nil
	case "-version", "--version":
		return runVersion(ctx, inv, args[1:])
	}
	c, ok := findCommand(args[0])
	if !ok {
		return exitcode.Errorf(exitcode.Usage, "unknown command %q (run 'ittcsecscan help')", args[0])
	}
	return c.run(ctx, inv, args[1:])
}

func writeUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("ittcsecscan: cross-domain cloud attack-path analysis. Read-only by default.\n\n")
	b.WriteString("Usage:\n  ittcsecscan <command> [flags]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-9s %s\n", c.name, c.summary)
	}
	b.WriteString("\nFlags:\n  -h, --help   Show this help\n  --version    Print build identity\n\n")
	b.WriteString("Run 'ittcsecscan help <command>' for a command's flags.\n")
	b.WriteString("Exit codes and configuration are documented in docs/cli.md.\n")
	_, _ = io.WriteString(w, b.String())
}

// commandSpec describes one command's help text.
type commandSpec struct {
	name        string
	synopsis    string
	description string
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("ittcsecscan "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are reported through run, help through writeCommandHelp
	return fs
}

// parse parses args. done is true when the caller must return err immediately:
// either help was printed (err == nil) or the arguments were invalid.
func parse(fs *flag.FlagSet, inv *invocation, spec commandSpec, args []string) (done bool, err error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeCommandHelp(inv.out, fs, spec)
			return true, nil
		}
		return true, exitcode.Errorf(exitcode.Usage, "%s: %v (run 'ittcsecscan help %s')", spec.name, err, spec.name)
	}
	if fs.NArg() > 0 {
		return true, exitcode.Errorf(exitcode.Usage, "%s: unexpected argument %q", spec.name, fs.Arg(0))
	}
	return false, nil
}

func writeCommandHelp(w io.Writer, fs *flag.FlagSet, spec commandSpec) {
	var b strings.Builder
	fmt.Fprintf(&b, "Usage:\n  %s\n\n%s\n\nFlags:\n", spec.synopsis, spec.description)
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	_, _ = io.WriteString(w, b.String())
}

// runtimeFlags are accepted by every command that loads configuration.
type runtimeFlags struct {
	config        string
	logLevel      string
	logFormat     string
	dataDir       string
	masterKeyFile string
}

func (r *runtimeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&r.config, "config", "", "configuration `file` (default: $"+config.EnvConfig+", then the per-user location)")
	fs.StringVar(&r.logLevel, "log-level", "", "log `level`: debug, info, warn, error (default info)")
	fs.StringVar(&r.logFormat, "log-format", "", "log `format` on stderr: text, json (default text)")
	fs.StringVar(&r.dataDir, "data-dir", "", "absolute path of the data `directory`")
	fs.StringVar(&r.masterKeyFile, "master-key-file", "", "absolute path of the master-key `file` (the path only, never the key)")
}

func (r *runtimeFlags) overrides() config.Overrides {
	return config.Overrides{
		ConfigPath: r.config, LogLevel: r.logLevel, LogFormat: r.logFormat,
		DataDir: r.dataDir, MasterKeyFile: r.masterKeyFile,
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runHelp(ctx context.Context, inv *invocation, args []string) error {
	switch len(args) {
	case 0:
		writeUsage(inv.out)
		return nil
	case 1:
		c, ok := findCommand(args[0])
		if !ok {
			return exitcode.Errorf(exitcode.Usage, "help: unknown command %q", args[0])
		}
		if c.name == "help" {
			writeUsage(inv.out)
			return nil
		}
		return c.run(ctx, inv, []string{"-h"})
	}
	return exitcode.Errorf(exitcode.Usage, "help: expected at most one command, got %d", len(args))
}

var versionSpec = commandSpec{
	name:        "version",
	synopsis:    "ittcsecscan version [--json]",
	description: "Print the build identity of this binary. Fields that cannot be determined are\nreported as \"unknown\". Configuration is not read, so this works even when it is invalid.",
}

func runVersion(_ context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(versionSpec.name)
	asJSON := fs.Bool("json", false, "print JSON (schemas/cli/v1/version.schema.json)")
	if done, err := parse(fs, inv, versionSpec, args); done {
		return err
	}

	info := version.Get()
	if *asJSON {
		return writeJSON(inv.out, info)
	}
	kind := ""
	if info.Development {
		kind = " (development build)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ittcsecscan %s%s\n", info.Version, kind)
	fmt.Fprintf(&b, "  commit:      %s\n", info.Commit)
	fmt.Fprintf(&b, "  source tree: %s\n", info.SourceTree)
	fmt.Fprintf(&b, "  built:       %s\n", info.BuildTime)
	fmt.Fprintf(&b, "  go:          %s\n", info.GoVersion)
	fmt.Fprintf(&b, "  platform:    %s/%s\n", info.OS, info.Arch)
	_, err := io.WriteString(inv.out, termsafe.String(b.String()))
	return err
}

var doctorSpec = commandSpec{
	name:     "doctor",
	synopsis: "ittcsecscan doctor [--json] [--strict] [runtime flags]",
	description: "Check the local environment and configuration. Doctor is read-only: it creates\n" +
		"nothing, writes nothing, and makes no network requests. A check that cannot be\n" +
		"evaluated is reported as unknown, never as a pass.\n\n" +
		"Exit status is 0 unless a check fails (4). With --strict, warnings and unknown\n" +
		"checks also exit 4.",
}

// readKeyUsage reads each tenant's data-key encryption count for doctor's
// data-keys check (B-6). It is read-only and creates nothing; an empty data
// directory means no tenants, not an error.
func readKeyUsage(ctx context.Context, dataDir string) ([]doctor.KeyUsage, error) {
	if dataDir == "" {
		return nil, nil
	}
	usage, err := store.ReadKeyUsage(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	out := make([]doctor.KeyUsage, len(usage))
	for i, u := range usage {
		out[i] = doctor.KeyUsage{Tenant: u.Tenant.String(), Sealed: u.Sealed, Warn: u.Warn, HardStop: u.HardStop}
	}
	return out, nil
}

func runDoctor(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(doctorSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	asJSON := fs.Bool("json", false, "print JSON (schemas/cli/v1/doctor.schema.json)")
	strict := fs.Bool("strict", false, "also fail on warnings and checks that cannot be evaluated")
	if done, err := parse(fs, inv, doctorSpec, args); done {
		return err
	}

	a := app.NewLenient(app.Options{Overrides: rf.overrides(), LookupEnv: inv.lookupEnv, Stderr: inv.err})
	env := doctor.HostEnvironment()
	env.Build = a.Build
	env.BuildTime, _ = a.Build.BuildTimestamp()
	env.ConfigSource = a.ConfigSource.String()
	env.ConfigFile = a.ConfigSource.File
	env.ConfigErr = a.ConfigErr
	env.DataDir = a.Config.DataDir
	env.KeyUsage, env.KeyUsageErr = readKeyUsage(ctx, a.Config.DataDir)
	env.AuthProviders = inv.resolver.Providers()

	rep, err := doctor.Run(ctx, doctor.Standard(env), *strict, a.Logger)
	if err != nil {
		return err
	}
	if *asJSON {
		err = writeJSON(inv.out, rep)
	} else {
		err = doctor.WriteText(inv.out, rep)
	}
	if err != nil {
		return err
	}
	if !rep.Passed() {
		return exitcode.Errorf(exitcode.DoctorFailed, "doctor: %d failed, %d warnings, %d unknown (strict=%t)",
			rep.Summary.Fail, rep.Summary.Warn, rep.Summary.Unknown, rep.Strict)
	}
	return nil
}
