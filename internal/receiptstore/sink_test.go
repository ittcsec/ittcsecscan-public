package receiptstore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/fsperm"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
	"github.com/ittcsec/ittcsecscan/internal/remediate/execute"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// okWriter is a stand-in provider writer that reports a captured prior state.
type okWriter struct{ prior string }

func (w okWriter) Apply(context.Context, execute.Operation) (execute.WriteResult, error) {
	return execute.WriteResult{PriorState: w.prior}, nil
}

func testStore(t *testing.T) *store.Tenant {
	t.Helper()
	base := t.TempDir()
	if reps, err := fsperm.InspectAncestors(filepath.Join(base, "probe")); err != nil || len(reps) > 0 {
		t.Skipf("temp dir %s is not private (%v); set TMP/TEMP to an owner-only folder", base, err)
	}
	key, err := store.NewMasterKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewStaticMasterKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(store.Options{DataDir: filepath.Join(base, "data"), Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	id, err := s.Create(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tn, release, err := s.Acquire(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return tn
}

// End to end: a real executor apply, through the sink, persists an immutable sealed receipt
// in the tenant store, closing Blocker C (the design's immutable-receipt
// requirement in the write-capable remediation path).
func TestApplyPersistsImmutableReceipt(t *testing.T) {
	tn := testStore(t)
	e := model.Entity{
		ID: model.StableID(strings.Repeat("a", 64)), Provider: model.AWS, Type: model.NodeDataStore,
		Name: "b", NativeID: "arn:aws:s3:::b", Attributes: map[string]string{"policy_is_public": "true"},
	}
	plan := remediate.Plan(model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS", Version: "1", PackID: "core-p0"}, e)
	at := time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	sink := New(tn, func() time.Time { return at })

	rec, err := execute.Apply(context.Background(),
		execute.Request{Plan: plan, Approval: plan.PlanHash, Profile: auth.Remediation, Current: e, Sink: sink},
		okWriter{prior: `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !rec.Applied {
		t.Fatal("apply did not mark the receipt applied")
	}

	got, err := tn.RemediationReceipts(context.Background())
	if err != nil {
		t.Fatalf("read receipts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("persisted %d receipts, want 1", len(got))
	}
	r := got[0]
	if !r.Applied || r.Rule != "CORE-P0-STORAGE-PUBLIC-AWS" || r.PlanHash != plan.PlanHash ||
		r.Profile != string(auth.Remediation) || r.PriorState != `{"Statement":[{"Effect":"Allow","Principal":"*"}]}` || !r.At.Equal(at) {
		t.Errorf("persisted receipt wrong: %+v", r)
	}
}
