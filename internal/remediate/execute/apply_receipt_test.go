package execute

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
)

type recordingSink struct {
	recs []Receipt
	err  error
}

func (s *recordingSink) Record(_ context.Context, r Receipt) error {
	s.recs = append(s.recs, r)
	return s.err
}

// A successful apply records exactly one immutable receipt, marked applied, with the prior
// state the writer captured (record an immutable receipt after
// verification). A mutation that skipped the sink leaves recs empty and fails this.
func TestApplyRecordsReceiptOnSuccess(t *testing.T) {
	p, e := fixture()
	sink := &recordingSink{}
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e, Sink: sink}, &recordingWriter{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !rec.Applied {
		t.Fatal("receipt not marked applied")
	}
	if len(sink.recs) != 1 {
		t.Fatalf("recorded %d receipts, want 1", len(sink.recs))
	}
	if got := sink.recs[0]; !got.Applied || got.PriorState != "recorded-prior-state" || got.PlanHash != p.PlanHash {
		t.Errorf("recorded receipt wrong: %+v", got)
	}
}

// A refused attempt is also recorded: the audit trail covers refusals, not just applied
// changes. Here the approval does not match the plan hash.
func TestApplyRecordsReceiptOnRefusal(t *testing.T) {
	p, e := fixture()
	sink := &recordingSink{}
	w := &recordingWriter{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: "wrong", Profile: auth.Remediation, Current: e, Sink: sink}, w)
	if !errors.Is(err, ErrApprovalMismatch) {
		t.Fatalf("want ErrApprovalMismatch, got %v", err)
	}
	if w.calls != 0 {
		t.Fatal("writer was called on a refused apply")
	}
	if len(sink.recs) != 1 || sink.recs[0].Applied || sink.recs[0].Refusal == "" {
		t.Fatalf("refusal receipt not recorded correctly: %+v", sink.recs)
	}
}

// If the receipt cannot be recorded after a successful apply, the failure is surfaced, never
// silent: the write happened but the operator is told it was not audited.
func TestApplyReceiptRecordFailureSurfaces(t *testing.T) {
	p, e := fixture()
	sink := &recordingSink{err: errors.New("store unavailable")}
	w := &recordingWriter{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e, Sink: sink}, w)
	if err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("a receipt record failure must surface, got %v", err)
	}
	if w.calls != 1 {
		t.Errorf("the write should still have happened once, got %d", w.calls)
	}
}

// A nil sink is allowed for plan-only and guard-behavior paths: apply still works and does
// not panic. (Real apply paths must supply a sink; that is enforced by the CLI wiring.)
func TestApplyNilSinkStillApplies(t *testing.T) {
	p, e := fixture()
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e, Sink: nil}, &recordingWriter{})
	if err != nil || !rec.Applied {
		t.Fatalf("nil-sink apply: err=%v applied=%v", err, rec.Applied)
	}
}
