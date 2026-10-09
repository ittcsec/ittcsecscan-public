package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

var awsKeyID = "AKIA" + "Z7CANARY0000TEST"

// hermetic returns an environment whose per-user directories are fresh
// temporary paths, so tests never read the real profile or configuration.
func hermetic(t *testing.T, extra map[string]string) config.LookupEnv {
	t.Helper()
	root := t.TempDir()
	env := map[string]string{
		"APPDATA":         filepath.Join(root, "appdata"),
		"LOCALAPPDATA":    filepath.Join(root, "localappdata"),
		"HOME":            filepath.Join(root, "home"),
		"XDG_CONFIG_HOME": filepath.Join(root, "xdgconfig"),
		"XDG_DATA_HOME":   filepath.Join(root, "xdgdata"),
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) (string, bool) { v, ok := env[k]; return v, ok }
}

type result struct {
	code exitcode.Code
	out  string
	err  string
}

// noSecret stands in for a terminal that is not available: every command that
// does not need a passphrase runs with it, and any that tried to read one would
// fail closed.
func noSecret(string) ([]byte, error) {
	return nil, errors.New("no terminal available to read a passphrase")
}

// queuedSecrets returns a secretReader that yields the given passphrases in
// order, so a keys test can drive the passphrase prompts.
func queuedSecrets(secrets ...string) secretReader {
	i := 0
	return func(string) ([]byte, error) {
		if i >= len(secrets) {
			return nil, errors.New("no more test passphrases")
		}
		s := secrets[i]
		i++
		return []byte(s), nil
	}
}

func invokeCtx(ctx context.Context, env config.LookupEnv, args ...string) result {
	var out, errb bytes.Buffer
	code := run(ctx, args, streams{out: &out, err: &errb}, env, noSecret, auth.NewRegistry())
	return result{code: code, out: out.String(), err: errb.String()}
}

// invokeSecrets runs a command with injected passphrase input.
func invokeSecrets(env config.LookupEnv, read secretReader, args ...string) result {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, streams{out: &out, err: &errb}, env, read, auth.NewRegistry())
	return result{code: code, out: out.String(), err: errb.String()}
}

// invokeResolver runs a command with an injected resolver, for the auth tests.
func invokeResolver(ctx context.Context, resolver *auth.Registry, env config.LookupEnv, args ...string) result {
	var out, errb bytes.Buffer
	code := run(ctx, args, streams{out: &out, err: &errb}, env, noSecret, resolver)
	return result{code: code, out: out.String(), err: errb.String()}
}

func invoke(t *testing.T, env config.LookupEnv, args ...string) result {
	t.Helper()
	return invokeCtx(context.Background(), env, args...)
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUsageErrors(t *testing.T) {
	env := hermetic(t, nil)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "no command given"},
		{"unknown command", []string{"nope"}, `unknown command "nope"`},
		{"unknown flag", []string{"version", "--nope"}, "flag provided but not defined"},
		{"unexpected argument", []string{"doctor", "extra"}, `unexpected argument "extra"`},
		{"help for unknown command", []string{"help", "nope"}, "unknown command"},
		{"help with two commands", []string{"help", "doctor", "version"}, "at most one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := invoke(t, env, tt.args...)
			if r.code != exitcode.Usage {
				t.Errorf("exit = %v, want usage", r.code)
			}
			if !strings.Contains(r.err, tt.want) {
				t.Errorf("stderr %q does not contain %q", r.err, tt.want)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	env := hermetic(t, nil)
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"help", "help"}} {
		r := invoke(t, env, args...)
		if r.code != exitcode.OK || !strings.Contains(r.out, "doctor") || !strings.Contains(r.out, "version") {
			t.Errorf("%v: exit=%v out=%q", args, r.code, r.out)
		}
	}
	r := invoke(t, env, "help", "doctor")
	if r.code != exitcode.OK || !strings.Contains(r.out, "--strict") || !strings.Contains(r.out, "read-only") {
		t.Errorf("help doctor: exit=%v out=%q", r.code, r.out)
	}
	r = invoke(t, env, "version", "-h")
	if r.code != exitcode.OK || !strings.Contains(r.out, "--json") {
		t.Errorf("version -h: exit=%v out=%q", r.code, r.out)
	}
}

func TestVersion(t *testing.T) {
	env := hermetic(t, nil)
	r := invoke(t, env, "version")
	if r.code != exitcode.OK || !strings.HasPrefix(r.out, "ittcsecscan ") || !strings.Contains(r.out, "platform:") {
		t.Errorf("version: exit=%v out=%q", r.code, r.out)
	}
	if alias := invoke(t, env, "--version"); alias.out != r.out {
		t.Errorf("--version output differs from version")
	}

	r = invoke(t, env, "version", "--json")
	if r.code != exitcode.OK {
		t.Fatalf("version --json: exit=%v stderr=%q", r.code, r.err)
	}
	if err := schema.ValidateJSON(schema.Version, []byte(r.out)); err != nil {
		t.Errorf("version --json violates its schema: %v\n%s", err, r.out)
	}
}

func TestVersionIgnoresBrokenConfiguration(t *testing.T) {
	env := hermetic(t, map[string]string{config.EnvConfig: writeConfig(t, `{broken`)})
	if r := invoke(t, env, "version"); r.code != exitcode.OK {
		t.Errorf("version must not depend on configuration: exit=%v stderr=%q", r.code, r.err)
	}
}

type doctorReport struct {
	Overall string `json:"overall"`
	Checks  []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

func decodeDoctor(t *testing.T, r result) doctorReport {
	t.Helper()
	if err := schema.ValidateJSON(schema.Doctor, []byte(r.out)); err != nil {
		t.Fatalf("doctor --json violates its schema: %v\n%s", err, r.out)
	}
	var rep doctorReport
	if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func checkStatus(rep doctorReport, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func TestDoctor(t *testing.T) {
	env := hermetic(t, nil)

	r := invoke(t, env, "doctor", "--json")
	// A test binary is a development build with no build time, so the best
	// possible result is warn: unknown is never reported as pass.
	if r.code != exitcode.OK {
		t.Fatalf("doctor: exit=%v stderr=%q out=%q", r.code, r.err, r.out)
	}
	rep := decodeDoctor(t, r)
	if rep.Overall != "warn" {
		t.Errorf("overall = %s, want warn", rep.Overall)
	}
	if got := checkStatus(rep, "clock.sanity"); got != "unknown" {
		t.Errorf("clock.sanity = %s, want unknown for a build without a build time", got)
	}
	if got := checkStatus(rep, "config.load"); got != "pass" {
		t.Errorf("config.load = %s", got)
	}

	strict := invoke(t, env, "doctor", "--strict")
	if strict.code != exitcode.DoctorFailed || !strings.Contains(strict.out, "Overall: WARN") || !strings.Contains(strict.err, "strict=true") {
		t.Errorf("doctor --strict: exit=%v out=%q err=%q", strict.code, strict.out, strict.err)
	}
}

func TestDoctorReportsInvalidConfigurationWithoutLeakingIt(t *testing.T) {
	cfg := writeConfig(t, `{"schema_version":1,"aws_secret_access_key":"`+awsKeyID+`"}`)
	env := hermetic(t, nil)
	r := invoke(t, env, "doctor", "--json", "--config", cfg)
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v, want doctor-failed", r.code)
	}
	rep := decodeDoctor(t, r)
	if rep.Overall != "fail" || checkStatus(rep, "config.load") != "fail" {
		t.Errorf("config failure not reported: %+v", rep)
	}
	if strings.Contains(r.out+r.err, awsKeyID) {
		t.Errorf("secret from configuration file reached the output")
	}
}

func TestDoctorAttributesBadFlags(t *testing.T) {
	env := hermetic(t, nil)
	r := invoke(t, env, "doctor", "--json", "--log-level", "loud")
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v", r.code)
	}
	rep := decodeDoctor(t, r)
	for _, c := range rep.Checks {
		if c.ID == "config.load" && !strings.Contains(c.Detail, "command-line flags") {
			t.Errorf("config.load detail does not attribute the flag: %q", c.Detail)
		}
	}
}

func TestDoctorTextIsTerminalSafe(t *testing.T) {
	// A hostile path in the environment must not reach the terminal raw.
	env := hermetic(t, map[string]string{config.EnvDataDir: filepath.Join(t.TempDir(), "evil\x1b[2Jdir")})
	r := invoke(t, env, "doctor")
	if strings.ContainsRune(r.out+r.err, '\x1b') {
		t.Errorf("escape sequence reached the terminal: %q", r.out)
	}
}

func TestInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := invokeCtx(ctx, hermetic(t, nil), "doctor")
	if r.code != exitcode.Interrupted || !strings.Contains(r.err, "interrupted") {
		t.Errorf("exit=%v stderr=%q", r.code, r.err)
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	r := invoke(t, hermetic(t, nil), "token="+awsKeyID)
	if r.code != exitcode.Usage || strings.Contains(r.err, awsKeyID) {
		t.Errorf("exit=%v stderr=%q", r.code, r.err)
	}
}
