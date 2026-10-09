package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/store"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// fakeSource is a scan source with canned identity and collectors, so the
// orchestration is tested without an SDK, a network, or real credentials.
type fakeSource struct {
	provider model.Provider
	account  string
	cols     []collect.Collector
	err      error
}

func (f fakeSource) Provider() model.Provider { return f.provider }
func (f fakeSource) Collectors(_ context.Context, _ *collect.Budget) (string, []collect.Collector, error) {
	return f.account, f.cols, f.err
}

// fakeCollector emits a fixed set of nodes and completeness into the sink, and
// optionally returns an error from Collect.
type fakeCollector struct {
	provider model.Provider
	emit     func(collect.Sink)
	err      error
}

func (f fakeCollector) ID() string                              { return "collector:fake" }
func (f fakeCollector) Provider() model.Provider                { return f.provider }
func (f fakeCollector) Requirements() []permissions.Requirement { return nil }
func (f fakeCollector) Collect(_ context.Context, s collect.Sink) error {
	if f.emit != nil {
		f.emit(s)
	}
	return f.err
}

// fakeIngester records the one merged input it is given.
type fakeIngester struct {
	calls  int
	last   store.ScanInput
	result store.Result
	err    error
}

func (f *fakeIngester) Ingest(_ context.Context, in store.ScanInput) (store.Result, error) {
	f.calls++
	f.last = in
	return f.result, f.err
}

// aNode emits one account node and one Complete completeness for the provider.
func emitComplete(p model.Provider, account string) func(collect.Sink) {
	return func(s collect.Sink) {
		_ = s.Node(collect.Node{Type: model.NodeAccount, NativeID: account, Name: "acme"})
		_ = s.Complete(collect.Completeness{Service: "iam", Region: collect.Global, Scope: collect.Scope{Account: account}, Status: collect.Complete, Collected: 1})
	}
}

func emitPartial(p model.Provider, account string) func(collect.Sink) {
	return func(s collect.Sink) {
		_ = s.Node(collect.Node{Type: model.NodeAccount, NativeID: account, Name: "acme"})
		_ = s.Complete(collect.Completeness{Service: "iam", Region: collect.Global, Scope: collect.Scope{Account: account}, Status: collect.Partial, Collected: 1, Reason: "throttled"})
	}
}

// budgetSpySource records the budget it was handed, so a test can prove the same
// shared budget reaches every provider.
type budgetSpySource struct {
	provider model.Provider
	got      **collect.Budget
}

func (s budgetSpySource) Provider() model.Provider { return s.provider }
func (s budgetSpySource) Collectors(_ context.Context, b *collect.Budget) (string, []collect.Collector, error) {
	*s.got = b
	return "", nil, errors.New("no collectors") // the budget capture is the point
}

// TestRunThreadsSharedBudgetToEverySource proves the budget is shared: the one
// budget passed to Run reaches every provider's Collectors, so the cap is on the
// whole scan, not per provider.
func TestRunThreadsSharedBudgetToEverySource(t *testing.T) {
	budget := collect.NewBudget(5)
	var b1, b2 *collect.Budget
	srcs := []Source{
		budgetSpySource{provider: model.AWS, got: &b1},
		budgetSpySource{provider: model.Azure, got: &b2},
	}
	if _, err := Run(context.Background(), "v", srcs, budget, &fakeIngester{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if b1 != budget || b2 != budget {
		t.Fatalf("sources did not all receive the one shared budget: b1=%p b2=%p budget=%p", b1, b2, budget)
	}
}

// TestRunIngestsAndReportsFullCoverage: one authenticated provider whose single
// enumeration completed becomes one ingest and a full-coverage report.
func TestRunIngestsAndReportsFullCoverage(t *testing.T) {
	src := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: emitComplete(model.AWS, "acct-1")}}}
	ing := &fakeIngester{result: store.Result{ScanID: 42, DroppedEdges: 0}}

	rep, err := Run(context.Background(), "v-test", []Source{src}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ing.calls != 1 {
		t.Fatalf("ingest calls = %d, want 1", ing.calls)
	}
	if rep.Authenticated != 1 {
		t.Errorf("authenticated = %d, want 1", rep.Authenticated)
	}
	if !rep.FullCoverage() {
		t.Error("FullCoverage = false, want true")
	}
	if rep.ScanID != 42 {
		t.Errorf("scan id = %d, want 42", rep.ScanID)
	}
	if got := len(ing.last.Entities); got != 1 {
		t.Errorf("ingested entities = %d, want 1", got)
	}
	if got := len(ing.last.Scopes); got != 1 || ing.last.Scopes[0].Provider != model.AWS {
		t.Errorf("scopes = %+v, want one aws scope", ing.last.Scopes)
	}
	if ing.last.ToolVersion != "v-test" {
		t.Errorf("tool version = %q, want v-test", ing.last.ToolVersion)
	}
}

// TestRunOneProviderAuthFailureDoesNotBlockOthers proves the isolation the maintainer
// required: a provider that cannot authenticate is recorded as a gap, the others
// still run and ingest, and the failed provider makes the scan incomplete (not a
// silent pass).
func TestRunOneProviderAuthFailureDoesNotBlockOthers(t *testing.T) {
	bad := fakeSource{provider: model.Azure, err: errors.New("azure: no credentials")}
	good := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: emitComplete(model.AWS, "acct-1")}}}
	ing := &fakeIngester{result: store.Result{ScanID: 7}}

	rep, err := Run(context.Background(), "v", []Source{bad, good}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ing.calls != 1 {
		t.Fatalf("ingest calls = %d, want 1 (only the authenticated provider)", ing.calls)
	}
	if rep.Authenticated != 1 {
		t.Errorf("authenticated = %d, want 1", rep.Authenticated)
	}
	if len(rep.Providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(rep.Providers))
	}
	if rep.Providers[0].AuthError == nil {
		t.Error("first provider: want recorded auth error")
	}
	if rep.Providers[1].AuthError != nil {
		t.Errorf("second provider: unexpected auth error %v", rep.Providers[1].AuthError)
	}
	if rep.FullCoverage() {
		t.Error("FullCoverage = true, want false (a provider failed to authenticate)")
	}
}

// TestRunNoProviderAuthenticatedDoesNotIngest proves an all-auth-failure scan
// writes nothing: never an empty scan that would read as a clean result.
func TestRunNoProviderAuthenticatedDoesNotIngest(t *testing.T) {
	src := fakeSource{provider: model.AWS, err: errors.New("aws: expired token")}
	ing := &fakeIngester{result: store.Result{ScanID: 99}}

	rep, err := Run(context.Background(), "v", []Source{src}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ing.calls != 0 {
		t.Fatalf("ingest calls = %d, want 0 (nothing authenticated)", ing.calls)
	}
	if rep.Authenticated != 0 {
		t.Errorf("authenticated = %d, want 0", rep.Authenticated)
	}
	if rep.ScanID != 0 {
		t.Errorf("scan id = %d, want 0 (no ingest happened)", rep.ScanID)
	}
	if rep.FullCoverage() {
		t.Error("FullCoverage = true, want false")
	}
}

// TestRunPartialCoverageStillIngests: a partial enumeration is stored (the data
// is real) but the scan is not full coverage.
func TestRunPartialCoverageStillIngests(t *testing.T) {
	src := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: emitPartial(model.AWS, "acct-1")}}}
	ing := &fakeIngester{result: store.Result{ScanID: 3}}

	rep, err := Run(context.Background(), "v", []Source{src}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ing.calls != 1 {
		t.Fatalf("ingest calls = %d, want 1", ing.calls)
	}
	if rep.FullCoverage() {
		t.Error("FullCoverage = true, want false (partial enumeration)")
	}
}

// TestRunAuthenticatedButNoCoverageIsNotFull: a provider that authenticated but
// recorded no completeness has not proven coverage.
func TestRunAuthenticatedButNoCoverageIsNotFull(t *testing.T) {
	src := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: func(s collect.Sink) {
			_ = s.Node(collect.Node{Type: model.NodeAccount, NativeID: "acct-1"})
		}}}}
	ing := &fakeIngester{result: store.Result{ScanID: 1}}

	rep, err := Run(context.Background(), "v", []Source{src}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.FullCoverage() {
		t.Error("FullCoverage = true, want false (no completeness recorded)")
	}
}

// TestRunCollectorErrorForcesIncomplete: a collector that reports Complete
// coverage but also returns an error must not let the scan read as full. A
// collection error is never turned into a pass.
func TestRunCollectorErrorForcesIncomplete(t *testing.T) {
	src := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: emitComplete(model.AWS, "acct-1"), err: errors.New("unexpected api failure")}}}
	ing := &fakeIngester{result: store.Result{ScanID: 8}}

	rep, err := Run(context.Background(), "v", []Source{src}, nil, ing)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ing.calls != 1 {
		t.Fatalf("ingest calls = %d, want 1 (partial data is still stored)", ing.calls)
	}
	if rep.Providers[0].CollectError == nil {
		t.Error("want recorded collect error")
	}
	if rep.FullCoverage() {
		t.Error("FullCoverage = true, want false (a collector errored)")
	}
}

// TestRunIngestErrorSurfaces: an ingest failure is returned, not swallowed.
func TestRunIngestErrorSurfaces(t *testing.T) {
	src := fakeSource{provider: model.AWS, account: "acct-1",
		cols: []collect.Collector{fakeCollector{provider: model.AWS, emit: emitComplete(model.AWS, "acct-1")}}}
	ing := &fakeIngester{err: errors.New("disk full")}

	if _, err := Run(context.Background(), "v", []Source{src}, nil, ing); err == nil {
		t.Fatal("Run: want ingest error, got nil")
	}
}
