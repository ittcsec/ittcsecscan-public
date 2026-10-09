package collect

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// fakeCollector runs an injected function, so tests model any collection outcome
// without a network or an SDK.
type fakeCollector struct {
	id string
	p  model.Provider
	fn func(ctx context.Context, sink Sink) error
}

func (f fakeCollector) ID() string                              { return f.id }
func (f fakeCollector) Provider() model.Provider                { return f.p }
func (f fakeCollector) Requirements() []permissions.Requirement { return nil }
func (f fakeCollector) Collect(ctx context.Context, sink Sink) error {
	return f.fn(ctx, sink)
}

func TestRunEmitsEvidenceAndCompleteness(t *testing.T) {
	c := fakeCollector{id: "collector:aws.iam.roles", p: model.AWS, fn: func(_ context.Context, s Sink) error {
		_ = s.Evidence(Envelope{Provider: model.AWS, Service: "iam", Operation: "ListRoles", Region: Global})
		return s.Complete(Completeness{Service: "iam", Region: Global, Status: Complete, Collected: 3})
	}}
	var sink Scan
	if err := Run(context.Background(), []Collector{c}, &sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sink.Envelopes) != 1 || len(sink.Completeness) != 1 || !sink.Completeness[0].Done() {
		t.Fatalf("unexpected sink state: %+v", sink)
	}
}

func TestRunContinuesAfterACollectorError(t *testing.T) {
	failing := fakeCollector{id: "a", p: model.AWS, fn: func(context.Context, Sink) error { return errors.New("boom") }}
	ok := fakeCollector{id: "b", p: model.AWS, fn: func(_ context.Context, s Sink) error {
		return s.Complete(Completeness{Service: "iam", Region: Global, Status: Complete})
	}}
	var sink Scan
	err := Run(context.Background(), []Collector{failing, ok}, &sink)
	if err == nil {
		t.Fatal("want the failing collector's error surfaced")
	}
	// The second collector still ran: one failure never silently drops the rest.
	if len(sink.Completeness) != 1 {
		t.Fatalf("second collector did not run: %+v", sink)
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	c := fakeCollector{id: "a", p: model.AWS, fn: func(context.Context, Sink) error { ran = true; return nil }}
	err := Run(ctx, []Collector{c}, &Scan{})
	if err == nil {
		t.Fatal("cancelled run should return the context error")
	}
	if ran {
		t.Error("a collector ran after cancellation")
	}
}

// TestBudgetExhaustionIsPartial models the rule that a collector which runs out
// of budget records Partial, never a silent truncation reported as Complete.
func TestBudgetExhaustionIsPartial(t *testing.T) {
	budget := NewBudget(2)
	c := fakeCollector{id: "a", p: model.AWS, fn: func(_ context.Context, s Sink) error {
		read := 0
		for {
			if !budget.Spend() {
				return s.Complete(Completeness{Service: "ec2", Region: "us-east-1", Status: Partial, Collected: read, Reason: "API budget exhausted"})
			}
			read++
			if read > 100 { // a page cap, so the test cannot loop forever
				return s.Complete(Completeness{Service: "ec2", Region: "us-east-1", Status: Complete, Collected: read})
			}
		}
	}}
	var sink Scan
	if err := Run(context.Background(), []Collector{c}, &sink); err != nil {
		t.Fatal(err)
	}
	got := sink.Completeness[0]
	if got.Status != Partial || got.Done() || got.Reason == "" {
		t.Fatalf("budget exhaustion not reported as an explained Partial: %+v", got)
	}
	if budget.Remaining() != 0 {
		t.Errorf("budget remaining = %d, want 0", budget.Remaining())
	}
}

// TestNilBudgetIsUnlimited proves the nil-is-unlimited contract: a nil Budget's
// Spend always succeeds, so "no --budget" threads nil and every collector's spend
// call is a harmless no-op.
func TestNilBudgetIsUnlimited(t *testing.T) {
	var b *Budget // nil
	for i := 0; i < 1000; i++ {
		if !b.Spend() {
			t.Fatalf("nil budget refused a spend at %d; nil must be unlimited", i)
		}
	}
	if b.Remaining() != math.MaxInt64 {
		t.Errorf("nil budget Remaining = %d, want unlimited", b.Remaining())
	}
}

// TestEnvelopeMatchesSchema proves the Go type's wire form satisfies the
// published schema.
func TestEnvelopeMatchesSchema(t *testing.T) {
	e := Envelope{
		Provider: model.AWS, Service: "iam", Operation: "ListRoles", Region: Global,
		CollectedAt: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
		Scope:       Scope{Account: "123456789012"},
		Response:    json.RawMessage(`{"roles":[]}`),
		Provenance:  Provenance{APIVersion: "2010-05-08", Collector: "collector:aws.iam.roles"},
	}
	if err := schema.ValidateValue(schema.CollectEnvelope, e); err != nil {
		t.Fatalf("envelope does not match its schema: %v", err)
	}
}
