// Package scan orchestrates one scan: for each provider source it resolves the
// identity, runs the collectors under a shared API budget, and ingests the
// merged result into the tenant's store in one transaction. It is provider- and
// store-neutral (the concrete adapters, collectors, and store are injected), so
// the whole flow is testable without a network, an SDK, or a real tenant.
package scan

import (
	"context"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/ingest"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// Source is one provider's contribution to a scan: it resolves the provider
// identity and returns its collectors, built with an authenticated read-only
// client and the scan's shared call budget. A resolution failure is a recorded
// gap, not a stopped scan. The budget is shared across every provider so the
// scan's total API cost is bounded; a nil budget is unlimited.
type Source interface {
	Provider() model.Provider
	Collectors(ctx context.Context, budget *collect.Budget) (account string, collectors []collect.Collector, err error)
}

// Ingester ingests a scan's rows atomically. *store.Tenant satisfies it; tests
// use a fake to prove the flow without a real store.
type Ingester interface {
	Ingest(ctx context.Context, in store.ScanInput) (store.Result, error)
}

// ProviderResult reports one provider's part of the scan.
type ProviderResult struct {
	Provider     model.Provider
	Account      string
	AuthError    error // set when the provider could not authenticate; its collectors did not run
	CollectError error // set when a collector returned an error, even if it also recorded coverage
	Completeness []collect.Completeness
	// Scan is the provider's freshly collected in-memory graph. It is kept so the
	// caller can analyze it in the same run (there is no store read-back that
	// rehydrates a scan); it is nil for a provider that did not authenticate.
	Scan collect.Scan
}

// Report is the outcome of a scan.
type Report struct {
	Providers     []ProviderResult
	ScanID        int64
	DroppedEdges  int
	Authenticated int // providers that authenticated
}

// FullCoverage reports whether every provider was covered completely: each
// authenticated, each with at least one completeness record, and every record
// Complete (nothing partial, denied, unsupported, or errored). A provider that
// failed to authenticate, or authenticated but recorded no coverage at all, is a
// gap: coverage is proven, never assumed, so an empty record set is not "full".
func (r Report) FullCoverage() bool {
	for _, p := range r.Providers {
		if p.AuthError != nil || p.CollectError != nil {
			return false
		}
		if len(p.Completeness) == 0 {
			return false
		}
		for _, c := range p.Completeness {
			if !c.Done() {
				return false
			}
		}
	}
	return true
}

// Run resolves and collects each source, merges the results into one scan
// input, and ingests it. A provider that cannot authenticate is recorded and
// skipped; the others still run and ingest, so one provider's failure never
// loses the rest. It returns the report even when no provider authenticated (the
// caller maps that to an exit code); it returns an error only when the ingest
// itself fails.
//
// The budget is the scan's shared cap on provider collection calls (a nil budget
// is unlimited). It is passed to every source, so it bounds the whole scan's API
// cost first-come-first-served: when it is exhausted, the remaining collectors
// record their coverage as Partial ("budget exhausted") rather than making more
// calls. Identity resolution is not counted against it (that happens inside each
// source's Collectors, before collection); only collection reads spend from it.
func Run(ctx context.Context, toolVersion string, sources []Source, budget *collect.Budget, tn Ingester) (Report, error) {
	started := time.Now().UTC()
	var rep Report
	var merged store.ScanInput

	for _, src := range sources {
		pr := ProviderResult{Provider: src.Provider()}
		account, collectors, err := src.Collectors(ctx, budget)
		if err != nil {
			pr.AuthError = err
			rep.Providers = append(rep.Providers, pr)
			continue
		}
		pr.Account = account
		rep.Authenticated++

		var s collect.Scan
		// A collector error is recorded, not fatal: the other providers still run
		// and the data collected so far is still ingested. It is kept on the
		// result so a collector that failed without recording a completeness gap
		// still forces the scan to be reported incomplete, never a silent pass.
		pr.CollectError = collect.Run(ctx, collectors, &s)
		pr.Completeness = s.Completeness
		pr.Scan = s
		rep.Providers = append(rep.Providers, pr)

		part := ingest.ToStore(s, ingest.Meta{ToolVersion: toolVersion, Provider: src.Provider(), Started: started})
		merged.Entities = append(merged.Entities, part.Entities...)
		merged.Edges = append(merged.Edges, part.Edges...)
		merged.Evidence = append(merged.Evidence, part.Evidence...)
		merged.Scopes = append(merged.Scopes, part.Scopes...)
	}

	// Nothing authenticated: there is nothing to ingest, and the caller reports
	// auth-failed. Never write an empty scan that would look like a clean result.
	if rep.Authenticated == 0 {
		return rep, nil
	}

	merged.ToolVersion = toolVersion
	merged.Started = started
	merged.Completed = time.Now().UTC()
	res, err := tn.Ingest(ctx, merged)
	if err != nil {
		return rep, err
	}
	rep.ScanID = res.ScanID
	rep.DroppedEdges = res.DroppedEdges
	return rep, nil
}
