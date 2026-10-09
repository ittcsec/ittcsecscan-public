package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/app"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/egress"
	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/graph"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/pipeline"
	"github.com/ittcsec/ittcsecscan/internal/report"
	"github.com/ittcsec/ittcsecscan/internal/rules/pack"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/internal/version"
	"github.com/ittcsec/ittcsecscan/packs"
	"github.com/ittcsec/ittcsecscan/providers"
)

var scanSpec = commandSpec{
	name:     "scan",
	synopsis: "ittcsecscan scan (--tenant <id> | --create) [--provider <list>] [--budget <n>] [--collect-only] [--fail-on-findings] [--json] [runtime flags]",
	description: "Collect a tenant's cloud graph, read-only, store it as a sealed, change-tracked\n" +
		"scan, then analyze it and report findings. For each provider it authenticates,\n" +
		"runs the read-only collectors, and ingests the result in one transaction. It then\n" +
		"normalizes the collected graph, computes internet-reachability exposure, and\n" +
		"evaluates the built-in detection packs, printing the findings. --collect-only\n" +
		"stops after storing, skipping analysis.\n\n" +
		"Exactly one of --tenant or --create is required. --tenant <id> scans an existing\n" +
		"tenant; --create makes a new tenant and prints its id (tenant ids are generated,\n" +
		"never chosen). --provider takes a comma-separated list of providers to scan\n" +
		"(default: every provider that has collectors).\n\n" +
		"--budget caps the number of provider collection calls the whole scan may make, so\n" +
		"its cost is predictable; 0 (the default) is unlimited. The budget is shared across\n" +
		"providers first-come-first-served: when it is exhausted, the remaining enumerations\n" +
		"are recorded as partial (reason: budget exhausted), never silently skipped. It\n" +
		"counts collection reads only; authenticating to each provider is not counted, so N\n" +
		"is not the total number of API calls a scan makes.\n\n" +
		"A finding whose supporting collection was incomplete is reported as unknown, never\n" +
		"as a pass. One provider failing to authenticate does not stop the others; its gap\n" +
		"is recorded. Exit status is 0 when every provider was covered completely, 5 when\n" +
		"any coverage gap remains (a partial, denied, or unsupported enumeration, a provider\n" +
		"that could not authenticate, or a budget-exhausted enumeration), and 7 when no\n" +
		"provider authenticated at all. With --fail-on-findings, a failing finding exits 6\n" +
		"and takes precedence over a coverage gap. The scan never reports a gap as success.",
}

// scanFlags are the scan-specific flags, beyond the shared runtime flags.
type scanFlags struct {
	tenant         string
	create         bool
	provider       string
	budget         int64
	asJSON         bool
	collectOnly    bool
	failOnFindings bool
	reportDir      string
	offlineAudit   string
}

func runScan(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(scanSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	var sf scanFlags
	fs.StringVar(&sf.tenant, "tenant", "", "the `id` of an existing tenant to scan")
	fs.BoolVar(&sf.create, "create", false, "create a new tenant and scan it (prints the new id)")
	fs.StringVar(&sf.provider, "provider", "", "comma-separated `list` of providers to scan (default: all with collectors)")
	fs.Int64Var(&sf.budget, "budget", 0, "max provider collection `calls` for the whole scan, 0 = unlimited (identity resolution is not counted; only collection reads are)")
	fs.BoolVar(&sf.asJSON, "json", false, "print JSON (schemas/cli/v1/scan.schema.json)")
	fs.BoolVar(&sf.collectOnly, "collect-only", false, "collect and store only; do not run the analysis pipeline or report findings")
	fs.BoolVar(&sf.failOnFindings, "fail-on-findings", false, "exit 6 when the analysis produces any failing finding (default: exit reflects coverage only)")
	fs.StringVar(&sf.reportDir, "report-dir", "", "write the report in all formats (JSON, SARIF, HTML, DOCX, PDF) to this `directory`")
	fs.StringVar(&sf.offlineAudit, "offline-audit", "", "write a zero-egress audit log of every outbound connection attempt to this `file`; observational only, so a user can confirm only the scanned provider's endpoints were contacted")
	if done, err := parse(fs, inv, scanSpec, args); done {
		return err
	}

	sources, err := selectSources(sf.provider, inv.lookupEnv)
	if err != nil {
		return err
	}
	// Validate the tenant flags before opening the store, so a flag mistake is
	// reported without prompting for a passphrase or touching any tenant.
	intent, err := resolveTenantIntent(sf)
	if err != nil {
		return err
	}

	// Open the store, which resolves the master key. This is where the
	// fail-closed guarantee bites: with no reachable master key the store refuses
	// and no tenant is created or scanned. It is never silently proceeded past.
	st, err := openStore(inv, rf)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	tn, id, release, err := intent.open(ctx, st)
	if err != nil {
		return err
	}
	defer release()

	// Zero-egress audit (item 6): when enabled, install the dial observer before any
	// provider call so every outbound connection attempt, including identity resolution,
	// is recorded to the operator-visible file. It is observational only.
	if sf.offlineAudit != "" {
		aud, err := egress.NewAuditor(sf.offlineAudit, id.String(), version.Get().Version)
		if err != nil {
			return err
		}
		collect.SetDialObserver(aud.Observe)
		defer func() {
			collect.SetDialObserver(nil)
			n, _ := aud.Close()
			_, _ = fmt.Fprintf(inv.out, "egress audit: %d connection attempts recorded in %s\n", n, sf.offlineAudit)
		}()
	}

	rep, err := scan.Run(ctx, version.Get().Version, sources, scanBudget(sf.budget), tn)
	if err != nil {
		return err
	}

	// Analysis runs by default: normalize each provider's freshly collected scan,
	// classify its assets, apply the tenant's audited criticality overrides,
	// materialize reachability exposure, and evaluate the built-in packs.
	// --collect-only keeps the historical collect-and-store-only behavior.
	analyzed := !sf.collectOnly
	var findings []pipeline.RankedFinding
	var classifications []model.Classification
	var paths []pipeline.RankedPath
	var cuts []model.CutSet
	identity := graph.EffectiveResult{Complete: true}
	if analyzed {
		trusted, err := pack.TrustedBuiltinKeys(packs.AllowedSigners())
		if err != nil {
			return err
		}
		ruleset, err := pack.LoadBuiltinAll(packs.FS, trusted)
		if err != nil {
			return err
		}
		overrides, err := tn.CriticalityOverrides(ctx)
		if err != nil {
			return err
		}
		keyer := tenantKeyer{tn: tn}
		for _, p := range rep.Providers {
			if p.AuthError != nil {
				continue // a provider that did not authenticate collected nothing to analyze
			}
			res, err := pipeline.AnalyzeScan(p.Scan, keyer, p.Provider, overrides, ruleset)
			if err != nil {
				return err
			}
			findings = append(findings, res.RankedFindings...)
			classifications = append(classifications, res.Classification.Classifications...)
			paths = append(paths, res.RankedPaths...)
			cuts = append(cuts, res.Cuts...)
			identity.Grants = append(identity.Grants, res.Identity.Grants...)
			if !res.Identity.Complete {
				identity.Complete = false
			}
			identity.Gaps = append(identity.Gaps, res.Identity.Gaps...)
		}
	}

	if err := writeScanResult(inv.out, sf.asJSON, analyzed, id, rep, findings, classifications, paths, cuts); err != nil {
		return err
	}
	if analyzed && sf.reportDir != "" {
		dv, err := tn.Diff(ctx, rep.ScanID)
		if err != nil {
			return err
		}
		rpt := report.Build(buildReportInput(id, rep, findings, classifications, paths, cuts, identity, dv))
		if err := writeReports(inv.out, sf.reportDir, rpt); err != nil {
			return err
		}
	}
	return scanExit(id, rep, analyzed, sf.failOnFindings, findings)
}

// tenantKeyer adapts *store.Tenant (whose StableID returns a string) to the
// repo.StableIDer normalize expects (which returns a model.StableID). It keys the
// analyzed graph's entities and edges with the same tenant-scoped HMAC ids
// persistence uses, so reachability joins resolve consistently with the stored
// scan, not with a test stand-in key.
type tenantKeyer struct{ tn *store.Tenant }

func (k tenantKeyer) StableID(nativeID string) (model.StableID, error) {
	id, err := k.tn.StableID(nativeID)
	return model.StableID(id), err
}

// selectSources returns the scan sources, filtered by a comma-separated provider
// list. An empty list means every scannable provider. A named provider that is
// not scannable (unknown, or a provider with no collectors yet) is a usage
// error that names what can be scanned, never a silent skip.
func selectSources(list string, lookupEnv config.LookupEnv) ([]scan.Source, error) {
	all := providers.ScanSources(lookupEnv)
	if strings.TrimSpace(list) == "" {
		return all, nil
	}
	byName := make(map[model.Provider]scan.Source, len(all))
	for _, s := range all {
		byName[s.Provider()] = s
	}
	var out []scan.Source
	seen := make(map[model.Provider]bool)
	for _, raw := range strings.Split(list, ",") {
		name := model.Provider(strings.ToLower(strings.TrimSpace(raw)))
		if name == "" {
			continue
		}
		s, ok := byName[name]
		if !ok {
			return nil, exitcode.Errorf(exitcode.Usage,
				"scan: provider %q cannot be scanned; scannable providers: %s", name, scannableNames(all))
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, exitcode.Errorf(exitcode.Usage, "scan: --provider selected no providers")
	}
	return out, nil
}

func scannableNames(sources []scan.Source) string {
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		names = append(names, string(s.Provider()))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// openStore loads configuration and opens the per-tenant store, wiring the
// operator master key from the configured key file. The master key is read
// lazily and can only ever be read, never created, so a store opened here fails
// closed (ADR-0015).
func openStore(inv *invocation, rf runtimeFlags) (*store.Store, error) {
	a, err := app.New(app.Options{Overrides: rf.overrides(), LookupEnv: inv.lookupEnv, Stderr: inv.err})
	if err != nil {
		return nil, err
	}
	if a.Config.DataDir == "" {
		return nil, exitcode.Errorf(exitcode.Usage,
			"scan: no data directory configured; set --data-dir or data_dir in the configuration")
	}
	if a.Config.MasterKeyFile == "" {
		return nil, exitcode.Errorf(exitcode.Usage,
			"scan: no master-key file configured; set --master-key-file or master_key_file in the configuration")
	}
	if inv.readSecret == nil {
		return nil, exitcode.Errorf(exitcode.Internal, "scan: cannot read a passphrase")
	}
	keys := store.NewFileMasterKeys(a.Config.MasterKeyFile, func() ([]byte, error) {
		return inv.readSecret("Enter the master-key passphrase: ")
	})
	return store.New(store.Options{DataDir: a.Config.DataDir, Keys: keys, Logger: a.Logger})
}

// tenantIntent is the validated choice of which tenant to scan: a new one to
// create, or a parsed existing id. It is resolved from the flags before the
// store is opened, so a flag error never reaches the master key.
type tenantIntent struct {
	create bool
	id     store.TenantID // the parsed --tenant id, when create is false
}

// resolveTenantIntent validates that exactly one of --tenant and --create was
// given and parses the id. Tenant ids are generated, never chosen, so --tenant
// must be a canonical id; a new tenant comes only from --create.
func resolveTenantIntent(sf scanFlags) (tenantIntent, error) {
	switch {
	case sf.create && sf.tenant != "":
		return tenantIntent{}, exitcode.Errorf(exitcode.Usage, "scan: give either --tenant or --create, not both")
	case sf.create:
		return tenantIntent{create: true}, nil
	case sf.tenant != "":
		id, err := store.ParseTenantID(sf.tenant)
		if err != nil {
			return tenantIntent{}, exitcode.Wrap(exitcode.Usage, err)
		}
		return tenantIntent{id: id}, nil
	default:
		return tenantIntent{}, exitcode.Errorf(exitcode.Usage, "scan: one of --tenant or --create is required")
	}
}

// open acquires the tenant to scan, creating it first when --create was given.
// Creating a tenant and acquiring an existing one both go through the master
// key, so either way an unreadable key fails closed here before anything is
// scanned.
func (ti tenantIntent) open(ctx context.Context, st *store.Store) (*store.Tenant, store.TenantID, func(), error) {
	id := ti.id
	if ti.create {
		created, err := st.Create(ctx)
		if err != nil {
			return nil, store.TenantID{}, nil, err
		}
		id = created
	}
	tn, release, err := st.Acquire(ctx, id)
	if err != nil {
		return nil, store.TenantID{}, nil, err
	}
	return tn, id, release, nil
}

// scanBudget turns the --budget flag into the scan's shared call cap: a positive
// value caps collection calls, and 0 (or less) means unlimited, which is a nil
// budget the collectors treat as no limit.
func scanBudget(n int64) *collect.Budget {
	if n <= 0 {
		return nil
	}
	return collect.NewBudget(n)
}

// scanExit maps a scan report to the process exit code. No provider authenticated
// is auth-failed (7). With --fail-on-findings, a failing finding is findings-at-
// threshold (6), which takes precedence over a coverage gap because it is the gate
// the operator explicitly opted into (the coverage gap is still printed). Otherwise
// any remaining coverage gap is scan-incomplete (5); a fully covered scan is OK. A
// gap is never OK, and findings gating never applies to a --collect-only scan.
func scanExit(id store.TenantID, rep scan.Report, analyzed, failOnFindings bool, findings []pipeline.RankedFinding) error {
	switch {
	case rep.Authenticated == 0:
		return exitcode.Errorf(exitcode.AuthFailed,
			"scan: no provider authenticated for tenant %s", id)
	case analyzed && failOnFindings && hasFailFindings(findings):
		return exitcode.Errorf(exitcode.FindingsAtThreshold,
			"scan: tenant %s has failing findings", id)
	case !rep.FullCoverage():
		return exitcode.Errorf(exitcode.ScanIncomplete,
			"scan: tenant %s scanned with coverage gaps", id)
	default:
		return nil
	}
}
