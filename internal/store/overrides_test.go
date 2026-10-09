package store

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestCriticalityOverridesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))

	sid1s, err := tn.StableID("arn:aws:s3:::a")
	if err != nil {
		t.Fatal(err)
	}
	sid2s, err := tn.StableID("arn:aws:s3:::b")
	if err != nil {
		t.Fatal(err)
	}
	sid1, sid2 := model.StableID(sid1s), model.StableID(sid2s)
	base := time.Now().UTC().Truncate(time.Millisecond)

	adds := []model.CriticalityOverride{
		{Entity: sid1, Criticality: 3, Actor: "alice", Reason: "prod customer data", At: base},
		{Entity: sid1, Criticality: 5, Actor: "bob", Reason: "raised for audit", At: base.Add(time.Minute)},
		{Entity: sid2, Criticality: 2, Actor: "carol", At: base.Add(2 * time.Minute)},
	}
	for _, ov := range adds {
		if err := tn.AddCriticalityOverride(ctx, ov); err != nil {
			t.Fatalf("add %+v: %v", ov, err)
		}
	}

	got, err := tn.CriticalityOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("history has %d entries, want 3 (append-only, full history retained)", len(got))
	}
	// Oldest first, decrypted correctly.
	if got[0].Actor != "alice" || got[0].Criticality != 3 || got[0].Reason != "prod customer data" {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[1].Actor != "bob" || got[1].Criticality != 5 {
		t.Errorf("entry 1 = %+v (latest for sid1 must be retained, not overwrite entry 0)", got[1])
	}
	if got[2].Actor != "carol" || got[2].Reason != "" {
		t.Errorf("entry 2 = %+v", got[2])
	}

	// The actor and reason are sealed at rest, not stored in plaintext.
	err = tn.withConn(ctx, func(c *sql.Conn) error {
		var actorSealed []byte
		if err := c.QueryRowContext(ctx, "SELECT actor_sealed FROM criticality_overrides WHERE override_id = 1").Scan(&actorSealed); err != nil {
			return err
		}
		if bytes.Contains(actorSealed, []byte("alice")) {
			t.Error("actor is stored in plaintext; it must be sealed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddCriticalityOverrideRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	good, _ := tn.StableID("arn:aws:s3:::a")
	now := time.Now().UTC()

	cases := map[string]model.CriticalityOverride{
		"criticality below 1": {Entity: model.StableID(good), Criticality: 0, Actor: "a", At: now},
		"empty actor":         {Entity: model.StableID(good), Criticality: 1, Actor: "", At: now},
		"invalid entity":      {Entity: "not-a-stable-id", Criticality: 1, Actor: "a", At: now},
		"zero timestamp":      {Entity: model.StableID(good), Criticality: 1, Actor: "a"},
	}
	for name, ov := range cases {
		if err := tn.AddCriticalityOverride(ctx, ov); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
	if got, _ := tn.CriticalityOverrides(ctx); len(got) != 0 {
		t.Errorf("a rejected override was still written: %d rows", len(got))
	}
}
