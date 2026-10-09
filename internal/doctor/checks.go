package doctor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/fsperm"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/version"
)

// Environment supplies the facts the standard checks inspect. Host access is
// injected so every check is testable without touching the machine.
type Environment struct {
	Build        version.Info
	BuildTime    time.Time // zero when unknown
	ConfigSource string
	// ConfigFile is the configuration file in use, or the one whose loading
	// failed; "" when no file is involved.
	ConfigFile string
	ConfigErr  error
	DataDir    string

	// KeyUsage is each tenant's data-key encryption count against the limits
	// (B-6), read by the caller from the store. KeyUsageErr is set instead when
	// the counts could not be read, so the check reports unknown rather than a
	// false pass.
	KeyUsage    []KeyUsage
	KeyUsageErr error

	// AuthProviders lists the providers that have a registered credential
	// adapter, from the resolver. It reports which providers ittcsecscan can
	// attempt to authenticate; it does not mean access has been verified (that
	// is 'auth plan'). Empty until the adapters ship, so the check reports
	// unknown rather than a false pass.
	AuthProviders []model.Provider

	GOOS      string
	GOARCH    string
	Now       func() time.Time
	Stat      func(name string) (fs.FileInfo, error)
	Inspect   func(path string) (fsperm.Report, error)
	Ancestors func(path string) ([]fsperm.Report, error)
	Elevated  func() (bool, error)
}

// HostEnvironment returns an Environment with host-dependent fields filled in.
func HostEnvironment() Environment {
	return Environment{
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Now,
		Stat:      os.Stat,
		Inspect:   fsperm.Inspect,
		Ancestors: fsperm.InspectAncestors,
		Elevated:  isElevated,
	}
}

// Standard returns the built-in checks in their stable order.
func Standard(env Environment) []Check {
	return []Check{
		{ID: "runtime.platform", Title: "Supported platform", Run: env.checkPlatform},
		{ID: "build.identity", Title: "Build identity", Run: env.checkBuild},
		{ID: "config.load", Title: "Configuration", Run: env.checkConfig},
		{ID: "config.permissions", Title: "Configuration file permissions", Run: env.checkConfigPermissions},
		{ID: "crypto.sha256", Title: "SHA-256 self-test", Run: checkSHA256},
		{ID: "clock.sanity", Title: "System clock", Run: env.checkClock},
		{ID: "filesystem.data_dir", Title: "Data directory", Run: env.checkDataDir},
		{ID: "store.data_keys", Title: "Data-key encryption limit", Run: env.checkDataKeys},
		{ID: "auth.readiness", Title: "Credential readiness", Run: env.checkAuth},
		{ID: "process.privileges", Title: "Least privilege", Run: env.checkPrivileges},
	}
}

// checkAuth reports whether ittcsecscan has a credential adapter for each
// provider. It makes no network call and verifies no access: it reports only
// which adapters exist. Providers without an adapter are unknown, never a pass,
// because nothing about their auth has been established. Verifying access is
// 'auth plan'.
func (e Environment) checkAuth(context.Context) Outcome {
	have := make(map[model.Provider]bool, len(e.AuthProviders))
	for _, p := range e.AuthProviders {
		have[p] = true
	}
	var ready, missing []string
	for _, p := range model.Providers {
		if have[p] {
			ready = append(ready, string(p))
		} else {
			missing = append(missing, string(p))
		}
	}
	switch {
	case len(ready) == 0:
		return Outcome{
			Status:      Unknown,
			Detail:      "no credential adapter is built yet (" + strings.Join(missing, ", ") + "); expected until the authentication adapters are built",
			Remediation: "run 'ittcsecscan auth plan' to check provider access once credential adapters ship",
		}
	case len(missing) > 0:
		return Outcome{
			Status:      Unknown,
			Detail:      "credential adapters available for " + strings.Join(ready, ", ") + "; none for " + strings.Join(missing, ", "),
			Remediation: "run 'ittcsecscan auth plan' to verify access for the available providers",
		}
	default:
		return Outcome{
			Status: Pass,
			Detail: "credential adapters available for " + strings.Join(ready, ", ") + "; run 'ittcsecscan auth plan' to verify access",
		}
	}
}

// KeyUsage is one tenant's data-key encryption count against the limits (B-6),
// supplied by the caller from the store.
type KeyUsage struct {
	Tenant   string
	Sealed   int64
	Warn     int64
	HardStop int64
}

// checkDataKeys reports whether any tenant's data key is near or past its
// encryption limit and should be rotated (B-6). A key that cannot be read is
// reported as unknown, never as a pass.
func (e Environment) checkDataKeys(context.Context) Outcome {
	if e.KeyUsageErr != nil {
		return Outcome{
			Status:      Unknown,
			Detail:      "cannot read the tenants' data-key encryption counts: " + e.KeyUsageErr.Error(),
			Remediation: "make the data directory readable",
		}
	}
	var exhausted, near int
	for _, u := range e.KeyUsage {
		switch {
		case u.Sealed >= u.HardStop:
			exhausted++
		case u.Sealed >= u.Warn:
			near++
		}
	}
	switch {
	case exhausted > 0:
		return Outcome{
			Status:      Fail,
			Detail:      fmt.Sprintf("%d of %d tenant data keys have reached the encryption limit and cannot seal", exhausted, len(e.KeyUsage)),
			Remediation: "rotate the affected tenants' data keys",
		}
	case near > 0:
		return Outcome{
			Status:      Warn,
			Detail:      fmt.Sprintf("%d of %d tenant data keys are near the encryption limit", near, len(e.KeyUsage)),
			Remediation: "rotate the affected tenants' data keys soon",
		}
	default:
		return Outcome{Status: Pass, Detail: fmt.Sprintf("%d tenant data keys are within the encryption limit", len(e.KeyUsage))}
	}
}

var supportedPlatforms = map[string]bool{
	"linux/amd64":   true,
	"linux/arm64":   true,
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"windows/amd64": true,
	"windows/arm64": true,
}

func (e Environment) checkPlatform(context.Context) Outcome {
	p := e.GOOS + "/" + e.GOARCH
	if !supportedPlatforms[p] {
		return Outcome{Status: Warn, Detail: p + " is not a tested release platform", Remediation: "use a supported platform: linux, darwin, or windows on amd64 or arm64"}
	}
	return Outcome{Status: Pass, Detail: p}
}

func (e Environment) checkBuild(context.Context) Outcome {
	b := e.Build
	switch {
	case b.Development:
		return Outcome{
			Status:      Warn,
			Detail:      fmt.Sprintf("development build %s (commit %s, source tree %s); not a reproducible release artifact", b.Version, b.Commit, b.SourceTree),
			Remediation: "use a release build for production scans",
		}
	case b.SourceTree != version.TreeClean:
		return Outcome{
			Status:      Warn,
			Detail:      fmt.Sprintf("release %s: source tree state is %s, want clean", b.Version, b.SourceTree),
			Remediation: "rebuild from a clean, tagged checkout with release/build.sh",
		}
	}
	return Outcome{Status: Pass, Detail: fmt.Sprintf("release %s (commit %s); binary signature verification is not available yet", b.Version, b.Commit)}
}

func (e Environment) checkConfig(context.Context) Outcome {
	if e.ConfigErr != nil {
		return Outcome{Status: Fail, Detail: e.ConfigErr.Error(), Remediation: "correct the configuration (see docs/cli.md); commands other than doctor and version refuse to run"}
	}
	return Outcome{Status: Pass, Detail: "using " + e.ConfigSource}
}

// finding is one observation that feeds a check's outcome.
type finding struct {
	status Status
	text   string
	fix    string
}

var severity = map[Status]int{Pass: 0, Unknown: 1, Warn: 2, Fail: 3}

// summarize reports the most severe findings, or pass when there are none.
func summarize(found []finding, pass string) Outcome {
	top := Pass
	for _, f := range found {
		if severity[f.status] > severity[top] {
			top = f.status
		}
	}
	if top == Pass {
		return Outcome{Status: Pass, Detail: pass}
	}
	var texts, fixes []string
	seen := map[string]bool{}
	for _, f := range found {
		if f.status != top {
			continue
		}
		texts = append(texts, f.text)
		if f.fix != "" && !seen[f.fix] {
			seen[f.fix] = true
			fixes = append(fixes, f.fix)
		}
	}
	return Outcome{Status: top, Detail: strings.Join(texts, "; "), Remediation: strings.Join(fixes, "; ")}
}

// ancestorFindings reports folders above path in which another account could
// rename or delete entries, and so substitute path with its own.
func (e Environment) ancestorFindings(path string, status Status) []finding {
	reps, err := e.Ancestors(path)
	if err != nil {
		return []finding{{status: Unknown, text: fmt.Sprintf("cannot evaluate the folders above %s: %v", path, err)}}
	}
	out := make([]finding, 0, len(reps))
	for _, r := range reps {
		out = append(out, finding{
			status: status,
			text:   fmt.Sprintf("other accounts can replace %s by renaming or deleting entries in %s: %s", path, r.Path, r.DescribeReplace()),
			fix:    "restrict delete and rename rights on that folder to your account, or use a location inside your user profile",
		})
	}
	return out
}

// checkConfigPermissions fails when another account can modify or replace
// the configuration file: it chooses where scan evidence is written. Other
// accounts reading it is acceptable because it never holds secrets.
func (e Environment) checkConfigPermissions(context.Context) Outcome {
	if e.ConfigFile == "" {
		return Outcome{Status: Pass, Detail: "no configuration file in use"}
	}
	var found []finding
	pass := e.ConfigFile + ": no other account can modify or replace it"
	rep, err := e.Inspect(e.ConfigFile)
	switch {
	case err != nil:
		found = append(found, finding{status: Unknown, text: fmt.Sprintf("cannot evaluate permissions of %s: %v", e.ConfigFile, err)})
	case rep.OthersCanWrite():
		found = append(found, finding{
			status: Fail,
			text:   fmt.Sprintf("%s can be modified by other accounts: %s", e.ConfigFile, rep.Describe()),
			fix:    "restrict write access to your account; another account could redirect data_dir or logging",
		})
	case rep.Incomplete != "":
		found = append(found, finding{status: Unknown, text: e.ConfigFile + ": " + rep.Incomplete})
	}
	if err == nil && rep.OthersCanRead() {
		pass += "; readable by " + rep.Describe() + ", acceptable because it holds no secrets"
	}
	found = append(found, e.ancestorFindings(e.ConfigFile, Fail)...)
	return summarize(found, pass)
}

// sha256KAT is the FIPS 180-4 example digest of "abc".
const sha256KAT = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func checkSHA256(context.Context) Outcome {
	sum := sha256.Sum256([]byte("abc"))
	if hex.EncodeToString(sum[:]) != sha256KAT {
		return Outcome{Status: Fail, Detail: "SHA-256 known-answer test failed; evidence hashes cannot be trusted", Remediation: "reinstall ittcsecscan from a verified release"}
	}
	return Outcome{Status: Pass, Detail: "known-answer test passed"}
}

func (e Environment) checkClock(context.Context) Outcome {
	if e.BuildTime.IsZero() {
		return Outcome{Status: Unknown, Detail: "build time is unknown for this build, so the clock cannot be bounded"}
	}
	now := e.Now().UTC()
	if now.Before(e.BuildTime) {
		return Outcome{
			Status:      Fail,
			Detail:      fmt.Sprintf("system clock %s is earlier than the build time %s", now.Format(time.RFC3339), e.BuildTime.Format(time.RFC3339)),
			Remediation: "correct the system clock; evidence timestamps and update-metadata expiry depend on it",
		}
	}
	return Outcome{Status: Pass, Detail: "system clock is later than the build time " + e.BuildTime.Format(time.RFC3339)}
}

// checkDataDir fails when other accounts can modify or replace the data
// directory (the local store must not live where others can alter it), and
// warns when they can read it or would inherit access to new files in it.
func (e Environment) checkDataDir(context.Context) Outcome {
	if e.DataDir == "" {
		return Outcome{Status: Fail, Detail: "the data directory could not be determined", Remediation: "set data_dir in the configuration file or ITTCSECSCAN_DATA_DIR"}
	}
	fi, err := e.Stat(e.DataDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return summarize(e.ancestorFindings(e.DataDir, Warn), e.DataDir+" does not exist yet (doctor never creates it)")
	case err != nil:
		return Outcome{Status: Fail, Detail: fmt.Sprintf("cannot inspect %s: %v", e.DataDir, err), Remediation: "make the directory accessible to your account"}
	case !fi.IsDir():
		return Outcome{Status: Fail, Detail: e.DataDir + " exists but is not a directory", Remediation: "point data_dir at a directory"}
	}

	var found []finding
	rep, err := e.Inspect(e.DataDir)
	switch {
	case err != nil:
		found = append(found, finding{status: Unknown, text: fmt.Sprintf("cannot evaluate permissions of %s: %v", e.DataDir, err)})
	case rep.OthersCanWrite():
		found = append(found, finding{
			status: Fail,
			text:   fmt.Sprintf("%s can be modified by other accounts: %s", e.DataDir, rep.Describe()),
			fix:    "restrict the directory to your account; the local store must not live where others can alter it",
		})
	case rep.OthersCanRead():
		found = append(found, finding{
			status: Warn,
			text:   fmt.Sprintf("%s is readable by other accounts: %s", e.DataDir, rep.Describe()),
			fix:    "restrict the directory to your account; scan evidence is sensitive",
		})
	case rep.Incomplete != "":
		found = append(found, finding{status: Unknown, text: e.DataDir + ": " + rep.Incomplete})
	}
	if err == nil && len(rep.Inherited) > 0 {
		found = append(found, finding{
			status: Warn,
			text:   fmt.Sprintf("files created in %s would inherit access for other accounts: %s", e.DataDir, rep.DescribeInherited()),
			fix:    "remove inheritable access from the directory (Windows: disable inheritance; Linux: remove the default ACL)",
		})
	}
	found = append(found, e.ancestorFindings(e.DataDir, Fail)...)
	return summarize(found, e.DataDir+": no other account can access it")
}

func (e Environment) checkPrivileges(context.Context) Outcome {
	elevated, err := e.Elevated()
	switch {
	case err != nil:
		return Outcome{Status: Unknown, Detail: fmt.Sprintf("cannot determine process privileges: %v", err)}
	case elevated:
		return Outcome{Status: Warn, Detail: "running with administrative privileges", Remediation: "run as an unprivileged user; ittcsecscan needs no local administrative rights"}
	}
	return Outcome{Status: Pass, Detail: "running without administrative privileges"}
}
