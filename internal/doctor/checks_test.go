package doctor

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/fsperm"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/version"
)

var buildTime = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

type fakeInfo struct {
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return "d" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return buildTime }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func private(path string) (fsperm.Report, error) { return fsperm.Report{Path: path}, nil }

func withReport(mutate func(*fsperm.Report)) func(string) (fsperm.Report, error) {
	return func(path string) (fsperm.Report, error) {
		r := fsperm.Report{Path: path}
		mutate(&r)
		return r, nil
	}
}

func exposed(read, write bool) func(string) (fsperm.Report, error) {
	return withReport(func(r *fsperm.Report) {
		r.Exposures = []fsperm.Exposure{{Principal: "Authenticated Users", Read: read, Write: write}}
	})
}

func noAncestors(string) ([]fsperm.Report, error) { return nil, nil }

func openAncestor(string) ([]fsperm.Report, error) {
	return []fsperm.Report{{Path: "/shared", Exposures: []fsperm.Exposure{{Principal: "others", Write: true, Replace: true}}}}, nil
}

func baseEnv() Environment {
	return Environment{
		Build:        version.Info{Version: "1.0.0", Commit: "abc", SourceTree: version.TreeClean},
		BuildTime:    buildTime,
		ConfigSource: "built-in defaults (no configuration file)",
		DataDir:      "/data",
		GOOS:         "linux",
		GOARCH:       "amd64",
		Now:          func() time.Time { return buildTime.Add(time.Hour) },
		Stat:         func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist },
		Inspect:      private,
		Ancestors:    noAncestors,
		Elevated:     func() (bool, error) { return false, nil },
	}
}

func outcome(t *testing.T, env Environment, id string) Outcome {
	t.Helper()
	for _, c := range Standard(env) {
		if c.ID == id {
			return c.Run(context.Background())
		}
	}
	t.Fatalf("no check %s", id)
	return Outcome{}
}

func expect(t *testing.T, env Environment, id string, want Status, detail string) {
	t.Helper()
	got := outcome(t, env, id)
	if got.Status != want {
		t.Errorf("%s status = %s, want %s (detail %q)", id, got.Status, want, got.Detail)
	}
	if !strings.Contains(got.Detail, detail) {
		t.Errorf("%s detail %q does not contain %q", id, got.Detail, detail)
	}
}

func TestStandardHealthyEnvironmentMatchesSchema(t *testing.T) {
	rep := run(t, false, Standard(baseEnv())...)
	if rep.Summary.Fail != 0 {
		t.Errorf("healthy environment failed: %+v", rep)
	}
	seen := map[string]bool{}
	for _, c := range rep.Checks {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestAuthReadinessCheck(t *testing.T) {
	// No adapters yet is the production state: unknown, never a pass, so
	// doctor never claims auth is verified when nothing has been checked. Under
	// --strict this correctly fails.
	expect(t, baseEnv(), "auth.readiness", Unknown, "no credential adapter is built yet")

	// All three adapters present: reports availability only, and says plainly
	// that access still has to be verified with auth plan.
	all := baseEnv()
	all.AuthProviders = model.Providers
	expect(t, all, "auth.readiness", Pass, "auth plan")

	// A partial set is still unknown overall: the missing providers are named.
	partial := baseEnv()
	partial.AuthProviders = []model.Provider{model.AWS}
	got := outcome(t, partial, "auth.readiness")
	if got.Status != Unknown {
		t.Fatalf("partial adapters status = %s, want unknown", got.Status)
	}
	if !strings.Contains(got.Detail, "none for azure, gcp") {
		t.Errorf("partial detail %q does not name the missing providers", got.Detail)
	}
}

func TestPlatformCheck(t *testing.T) {
	expect(t, baseEnv(), "runtime.platform", Pass, "linux/amd64")
	env := baseEnv()
	env.GOOS, env.GOARCH = "plan9", "386"
	expect(t, env, "runtime.platform", Warn, "plan9/386")
}

func TestBuildCheck(t *testing.T) {
	expect(t, baseEnv(), "build.identity", Pass, "release 1.0.0")

	env := baseEnv()
	env.Build.Development = true
	expect(t, env, "build.identity", Warn, "development build")

	env = baseEnv()
	env.Build.SourceTree = version.TreeModified
	expect(t, env, "build.identity", Warn, "modified")

	env = baseEnv()
	env.Build.SourceTree = version.Unknown
	expect(t, env, "build.identity", Warn, "unknown")
}

func TestConfigCheck(t *testing.T) {
	expect(t, baseEnv(), "config.load", Pass, "defaults")
	env := baseEnv()
	env.ConfigErr = errors.New("configuration file x: duplicate key")
	expect(t, env, "config.load", Fail, "duplicate key")
}

func TestConfigPermissionsCheck(t *testing.T) {
	expect(t, baseEnv(), "config.permissions", Pass, "no configuration file")

	env := baseEnv()
	env.ConfigFile = "/etc/ittcsecscan.json"
	expect(t, env, "config.permissions", Pass, "no other account can modify or replace it")

	env.Inspect = exposed(true, false)
	expect(t, env, "config.permissions", Pass, "acceptable because it holds no secrets")

	env.Inspect = exposed(true, true)
	expect(t, env, "config.permissions", Fail, "Authenticated Users (read, write)")

	env.Inspect = func(string) (fsperm.Report, error) { return fsperm.Report{}, errors.ErrUnsupported }
	expect(t, env, "config.permissions", Unknown, "cannot evaluate")

	env.Inspect = withReport(func(r *fsperm.Report) { r.Incomplete = "macOS ACLs are not inspected" })
	expect(t, env, "config.permissions", Unknown, "macOS ACLs are not inspected")

	env.Inspect = private
	env.Ancestors = openAncestor
	expect(t, env, "config.permissions", Fail, "renaming or deleting entries in /shared")

	env.Ancestors = func(string) ([]fsperm.Report, error) { return nil, errors.New("access denied") }
	expect(t, env, "config.permissions", Unknown, "cannot evaluate the folders above")
}

func TestSHA256Check(t *testing.T) {
	expect(t, baseEnv(), "crypto.sha256", Pass, "known-answer")
}

func TestClockCheck(t *testing.T) {
	expect(t, baseEnv(), "clock.sanity", Pass, "later than")

	env := baseEnv()
	env.Now = func() time.Time { return buildTime.Add(-time.Hour) }
	expect(t, env, "clock.sanity", Fail, "earlier than")

	env = baseEnv()
	env.BuildTime = time.Time{}
	expect(t, env, "clock.sanity", Unknown, "unknown")
}

func TestDataDirCheck(t *testing.T) {
	expect(t, baseEnv(), "filesystem.data_dir", Pass, "does not exist yet")

	missing := baseEnv()
	missing.Ancestors = openAncestor
	expect(t, missing, "filesystem.data_dir", Warn, "renaming or deleting entries in /shared")

	env := baseEnv()
	env.DataDir = ""
	expect(t, env, "filesystem.data_dir", Fail, "could not be determined")

	env = baseEnv()
	env.Stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	expect(t, env, "filesystem.data_dir", Fail, "cannot inspect")

	env = baseEnv()
	env.Stat = func(string) (fs.FileInfo, error) { return fakeInfo{mode: 0o600}, nil }
	expect(t, env, "filesystem.data_dir", Fail, "not a directory")

	dir := baseEnv()
	dir.Stat = func(string) (fs.FileInfo, error) { return fakeInfo{mode: fs.ModeDir | 0o700}, nil }
	expect(t, dir, "filesystem.data_dir", Pass, "no other account can access it")

	dir.Inspect = exposed(true, false)
	expect(t, dir, "filesystem.data_dir", Warn, "readable by other accounts")

	dir.Inspect = exposed(true, true)
	expect(t, dir, "filesystem.data_dir", Fail, "can be modified by other accounts")

	dir.Inspect = func(string) (fsperm.Report, error) { return fsperm.Report{}, errors.ErrUnsupported }
	expect(t, dir, "filesystem.data_dir", Unknown, "cannot evaluate")

	dir.Inspect = withReport(func(r *fsperm.Report) { r.Incomplete = "macOS ACLs are not inspected" })
	expect(t, dir, "filesystem.data_dir", Unknown, "macOS ACLs are not inspected")

	dir.Inspect = withReport(func(r *fsperm.Report) {
		r.Inherited = []fsperm.Exposure{{Principal: "Authenticated Users", Read: true, Write: true}}
	})
	expect(t, dir, "filesystem.data_dir", Warn, "would inherit access for other accounts: Authenticated Users (read, write)")

	// The most severe finding wins, and a readable directory under a
	// replaceable parent fails.
	dir.Inspect = exposed(true, false)
	dir.Ancestors = openAncestor
	expect(t, dir, "filesystem.data_dir", Fail, "renaming or deleting entries in /shared")
}

func TestPrivilegeCheck(t *testing.T) {
	expect(t, baseEnv(), "process.privileges", Pass, "without")

	env := baseEnv()
	env.Elevated = func() (bool, error) { return true, nil }
	expect(t, env, "process.privileges", Warn, "administrative")

	env = baseEnv()
	env.Elevated = func() (bool, error) { return false, errors.ErrUnsupported }
	expect(t, env, "process.privileges", Unknown, "cannot determine")
}

func TestHostEnvironmentRuns(t *testing.T) {
	env := HostEnvironment()
	env.Build = version.Get()
	env.ConfigSource = "test"
	env.DataDir = t.TempDir()
	rep := run(t, false, Standard(env)...)
	if len(rep.Checks) != len(Standard(env)) {
		t.Errorf("got %d results", len(rep.Checks))
	}
	for _, c := range rep.Checks {
		if c.ID != "filesystem.data_dir" {
			continue
		}
		// macOS results are honestly incomplete (ACLs are not read); every
		// other supported platform must be able to evaluate the directory.
		// Pass, warn, or fail all depend on the host's temp folder permissions,
		// which are outside the test's control.
		if runtime.GOOS != "darwin" && c.Status == Unknown {
			t.Errorf("data directory could not be evaluated on %s: %s", runtime.GOOS, c.Detail)
		}
	}
}

func TestCheckDataKeys(t *testing.T) {
	within := baseEnv()
	within.KeyUsage = []KeyUsage{{Tenant: "a", Sealed: 10, Warn: 100, HardStop: 200}}
	expect(t, within, "store.data_keys", Pass, "within the encryption limit")

	near := baseEnv()
	near.KeyUsage = []KeyUsage{
		{Tenant: "a", Sealed: 10, Warn: 100, HardStop: 200},
		{Tenant: "b", Sealed: 150, Warn: 100, HardStop: 200},
	}
	expect(t, near, "store.data_keys", Warn, "near the encryption limit")

	exhausted := baseEnv()
	exhausted.KeyUsage = []KeyUsage{{Tenant: "a", Sealed: 200, Warn: 100, HardStop: 200}}
	expect(t, exhausted, "store.data_keys", Fail, "cannot seal")

	unreadable := baseEnv()
	unreadable.KeyUsageErr = errors.New("permission denied")
	expect(t, unreadable, "store.data_keys", Unknown, "cannot read")
}
