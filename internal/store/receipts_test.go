package store

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func fixtureReceipt(t *testing.T, tn *Tenant) RemediationReceipt {
	t.Helper()
	sid, err := tn.StableID("arn:aws:s3:::pub")
	if err != nil {
		t.Fatal(err)
	}
	return RemediationReceipt{
		Entity: model.StableID(sid), Rule: "CORE-P0-STORAGE-PUBLIC-AWS", PlanHash: "abc123",
		Profile: "remediation", Action: "delete-bucket-policy", Applied: true,
		PriorState: `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`,
		At:         time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	}
}

// A receipt round-trips: what is written is read back, with the sealed prior state and
// refusal decrypted.
func TestRemediationReceiptRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	want := fixtureReceipt(t, tn)
	if err := tn.AddRemediationReceipt(context.Background(), want); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, err := tn.RemediationReceipts(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d receipts, want 1", len(got))
	}
	r := got[0]
	if r.Entity != want.Entity || r.Rule != want.Rule || r.PlanHash != want.PlanHash ||
		r.Profile != want.Profile || r.Action != want.Action || !r.Applied ||
		r.PriorState != want.PriorState || !r.At.Equal(want.At) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", r, want)
	}
}

// The prior state is sealed at rest: the plaintext never appears in the stored column. This
// is the sealing guarantee; a mutation that stored it in the clear breaks this test.
func TestRemediationReceiptIsSealedAtRest(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	rec := fixtureReceipt(t, tn)
	rec.Refusal = "a distinctive refusal reason"
	if err := tn.AddRemediationReceipt(context.Background(), rec); err != nil {
		t.Fatalf("add: %v", err)
	}
	err := tn.withConn(context.Background(), func(c *sql.Conn) error {
		var prior, refusal []byte
		if err := c.QueryRowContext(context.Background(),
			"SELECT prior_state_sealed, refusal_sealed FROM remediation_receipts").Scan(&prior, &refusal); err != nil {
			return err
		}
		if len(prior) == 0 || bytes.Contains(prior, []byte(rec.PriorState)) {
			t.Errorf("prior state is not sealed at rest (empty or plaintext present)")
		}
		if len(refusal) == 0 || bytes.Contains(refusal, []byte(rec.Refusal)) {
			t.Errorf("refusal is not sealed at rest (empty or plaintext present)")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The log is append-only: successive receipts accumulate, oldest first, none overwritten.
func TestRemediationReceiptsAppendOnly(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	first := fixtureReceipt(t, tn)
	first.PlanHash = "first"
	second := fixtureReceipt(t, tn)
	second.PlanHash = "second"
	second.Applied = false
	second.Refusal = "drift"
	for _, r := range []RemediationReceipt{first, second} {
		if err := tn.AddRemediationReceipt(context.Background(), r); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	got, err := tn.RemediationReceipts(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 2 || got[0].PlanHash != "first" || got[1].PlanHash != "second" {
		t.Fatalf("append-only order wrong: %+v", got)
	}
	if got[1].Applied || got[1].Refusal != "drift" {
		t.Errorf("second receipt not preserved: %+v", got[1])
	}
}

// AddRemediationReceipt fails closed on missing required fields, never writing a partial or
// unattributable receipt.
func TestRemediationReceiptValidation(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	base := fixtureReceipt(t, tn)
	cases := map[string]func(*RemediationReceipt){
		"bad entity": func(r *RemediationReceipt) { r.Entity = "not-a-stable-id" },
		"empty rule": func(r *RemediationReceipt) { r.Rule = "" },
		"empty hash": func(r *RemediationReceipt) { r.PlanHash = "" },
		"no profile": func(r *RemediationReceipt) { r.Profile = "" },
		"zero time":  func(r *RemediationReceipt) { r.At = time.Time{} },
	}
	for name, mangle := range cases {
		r := base
		mangle(&r)
		if err := tn.AddRemediationReceipt(context.Background(), r); err == nil {
			t.Errorf("%s: expected a fail-closed error, got nil", name)
		}
	}
}
