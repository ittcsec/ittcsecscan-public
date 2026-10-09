package execute

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
)

type recordingWriter struct {
	calls int
	last  Operation
}

func (w *recordingWriter) Apply(_ context.Context, op Operation) (WriteResult, error) {
	w.calls++
	w.last = op
	return WriteResult{PriorState: "recorded-prior-state"}, nil
}

func bucket() model.Entity {
	return model.Entity{
		ID: model.StableID(strings.Repeat("a", 64)), Provider: model.AWS, Type: model.NodeDataStore,
		Name: "b", NativeID: "arn:aws:s3:::b", Attributes: map[string]string{"policy_is_public": "true"},
	}
}

func fixture() (remediate.GeneratedPlan, model.Entity) {
	e := bucket()
	p := remediate.Plan(model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS", Version: "1", PackID: "core-p0"}, e)
	return p, e
}

// The separate-credential invariant: a read-only scanning profile is refused and
// the writer is never called.
func TestApplyRefusesReadOnlyProfile(t *testing.T) {
	p, e := fixture()
	for _, prof := range []auth.Profile{auth.Discovery, auth.DeepEvidence, ""} {
		w := &recordingWriter{}
		rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: prof, Current: e}, w)
		if !errors.Is(err, ErrWrongProfile) {
			t.Errorf("profile %q: want ErrWrongProfile, got %v", prof, err)
		}
		if w.calls != 0 {
			t.Errorf("profile %q: writer was called %d times; a refused apply must never write", prof, w.calls)
		}
		if rec.Applied {
			t.Errorf("profile %q: receipt marked applied on refusal", prof)
		}
	}
}

// Approval must bind to the exact plan hash.
func TestApplyRefusesApprovalMismatch(t *testing.T) {
	p, e := fixture()
	w := &recordingWriter{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: "not-the-hash", Profile: auth.Remediation, Current: e}, w)
	if !errors.Is(err, ErrApprovalMismatch) {
		t.Errorf("want ErrApprovalMismatch, got %v", err)
	}
	if w.calls != 0 {
		t.Errorf("writer called on approval mismatch")
	}
}

// Drift immediately before apply refuses and never writes.
func TestApplyRefusesOnDrift(t *testing.T) {
	p, _ := fixture()
	drifted := bucket()
	drifted.Attributes["policy_is_public"] = "false" // state changed since the plan
	w := &recordingWriter{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: drifted}, w)
	if !errors.Is(err, remediate.ErrDrift) {
		t.Errorf("want ErrDrift, got %v", err)
	}
	if w.calls != 0 {
		t.Errorf("writer called despite drift")
	}
}

// A named-gap plan (no apply-ready action) is refused.
func TestApplyRefusesGapPlan(t *testing.T) {
	e := model.Entity{ID: model.StableID(strings.Repeat("a", 64)), Provider: model.AWS, Type: model.NodeCompute}
	gap := remediate.Plan(model.RuleRef{RuleID: "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS", Version: "1", PackID: "core-p0"}, e)
	w := &recordingWriter{}
	_, err := Apply(context.Background(), Request{Plan: gap, Approval: gap.PlanHash, Profile: auth.Remediation, Current: e}, w)
	if !errors.Is(err, ErrNoAction) {
		t.Errorf("want ErrNoAction for a gap plan, got %v", err)
	}
	if w.calls != 0 {
		t.Errorf("writer called for a gap plan")
	}
}

// When every guard passes, the writer is called exactly once with the smallest
// action, and the receipt records the apply.
func TestApplyHappyPathCallsWriterOnce(t *testing.T) {
	p, e := fixture()
	w := &recordingWriter{}
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e}, w)
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if w.calls != 1 {
		t.Errorf("writer called %d times, want 1", w.calls)
	}
	if !rec.Applied {
		t.Error("receipt not marked applied on success")
	}
	if w.last.Action.Service != p.Actions[0].Service {
		t.Error("writer did not receive the smallest (first) action")
	}
	if w.last.Target.NativeID != e.NativeID || w.last.Rule.RuleID != p.Finding.RuleID {
		t.Error("writer did not receive the target entity and rule for a structured write")
	}
	if rec.PriorState != "recorded-prior-state" {
		t.Errorf("receipt did not preserve the captured prior state: %q", rec.PriorState)
	}
}

// The never-write-without-opt-in guarantee for the default build: execution is
// compiled out, and even a fully valid request cannot write. Flipping the disabled
// writer to return nil (pretending success) makes this fail.
func TestDefaultBuildCannotWrite(t *testing.T) {
	if Enabled {
		t.Skip("built with the remediation tag; this guard covers the default build")
	}
	p, e := fixture()
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e}, DefaultWriter())
	if !errors.Is(err, ErrExecutionDisabled) {
		t.Fatalf("default build must refuse to write even a valid request, got %v", err)
	}
	if rec.Applied {
		t.Error("default build marked a write as applied")
	}
}
