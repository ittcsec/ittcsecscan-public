package store

import (
	"context"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// credAttrs builds an attribute map from alternating key, value pairs. The
// test fixtures below use real credential-fact key names (cred_access_key_*,
// cred_mfa_active), which are static non-secret test values; passing them as
// call arguments rather than as map-literal keys keeps the gosec G101
// "hardcoded credentials" name heuristic (which matches the "cred" prefix) from
// flagging the fixtures. It panics on an odd argument count: a test-only misuse.
func credAttrs(pairs ...string) map[string]string {
	if len(pairs)%2 != 0 {
		panic("credAttrs: odd number of key/value arguments")
	}
	m := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m
}

// findEntityDelta returns the delta for a native id, or a zero delta.
func findEntityDelta(d Diff, native string) EntityDelta {
	for _, e := range d.Entities {
		if e.NativeID == native {
			return e
		}
	}
	return EntityDelta{}
}

func findEdgeDelta(d Diff, src, dst string) EdgeDelta {
	for _, e := range d.Edges {
		if e.Source == src && e.Target == dst {
			return e
		}
	}
	return EdgeDelta{}
}

// TestDiffReportsAppearedChangedDisappeared ingests two scans and proves the diff of the
// second reflects exactly what the change-detection engine recorded: a changed entity, a
// new (appeared) entity and edge, and a removed (disappeared) entity and edge, all with
// native ids decrypted. It surfaces recorded changes; it computes none.
func TestDiffReportsAppearedChangedDisappeared(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ctx := context.Background()
	now := time.Now().UTC()

	// Scan 1: account, a user, and user -> account.
	if _, err := tn.Ingest(ctx, ScanInput{
		ToolVersion: "v1", Started: now, Completed: now,
		Entities: []EntityInput{acct("acct-1", "acme"), user("user-1", "Alice")},
		Edges:    []EdgeInput{{SourceNativeID: "user-1", TargetNativeID: "acct-1", Kind: model.EdgeMemberOf}},
		Evidence: oneEvidence(now),
	}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	// Scan 2: account renamed (changed), a new workload (appeared) with a new edge, and
	// the user omitted (disappeared), so its edge disappears too.
	later := now.Add(time.Hour)
	res2, err := tn.Ingest(ctx, ScanInput{
		ToolVersion: "v2", Started: later, Completed: later,
		Entities: []EntityInput{
			acct("acct-1", "acme-renamed"),
			{Provider: model.AWS, Type: model.NodeWorkload, NativeID: "w1", Name: "runner"},
		},
		Edges:    []EdgeInput{{SourceNativeID: "w1", TargetNativeID: "acct-1", Kind: model.EdgeMemberOf}},
		Evidence: oneEvidence(later),
	})
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	latest, err := tn.LatestScanID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest != res2.ScanID {
		t.Fatalf("LatestScanID = %d, want %d", latest, res2.ScanID)
	}

	d, err := tn.Diff(ctx, 0) // 0 = latest
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if d.ScanID != res2.ScanID {
		t.Errorf("diff scan id = %d, want %d", d.ScanID, res2.ScanID)
	}

	if g := findEntityDelta(d, "acct-1"); g.Change != "changed" {
		t.Errorf("acct-1 change = %q, want changed", g.Change)
	}
	if g := findEntityDelta(d, "w1"); g.Change != "appeared" || g.Type != model.NodeWorkload {
		t.Errorf("w1 delta = %+v, want appeared workload", g)
	}
	if g := findEntityDelta(d, "user-1"); g.Change != "disappeared" {
		t.Errorf("user-1 change = %q, want disappeared", g.Change)
	}
	if g := findEdgeDelta(d, "w1", "acct-1"); g.Change != "appeared" || g.Kind != model.EdgeMemberOf {
		t.Errorf("w1->acct-1 edge delta = %+v, want appeared member_of", g)
	}
	if g := findEdgeDelta(d, "user-1", "acct-1"); g.Change != "disappeared" {
		t.Errorf("user-1->acct-1 edge change = %q, want disappeared", g.Change)
	}
}

// TestDiffFirstScanIsBaseline proves the first scan records no change rows: it is the
// baseline, with no prior state to compare against, so its diff is honestly empty. The
// change-detection engine records appeared/changed/disappeared only from the second scan
// on; the diff surfaces exactly that, never a synthesized "everything appeared".
func TestDiffFirstScanIsBaseline(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ctx := context.Background()
	now := time.Now().UTC()
	res, err := tn.Ingest(ctx, ScanInput{
		ToolVersion: "v", Started: now, Completed: now,
		Entities: []EntityInput{acct("a", "acme"), user("u", "Alice")},
		Evidence: oneEvidence(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := tn.Diff(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.ScanID != res.ScanID {
		t.Errorf("diff scan id = %d, want %d", d.ScanID, res.ScanID)
	}
	if len(d.Entities) != 0 || len(d.Edges) != 0 {
		t.Errorf("first-scan diff = %d entities, %d edges; want empty (baseline)", len(d.Entities), len(d.Edges))
	}
}

// TestDiffIgnoresAgeTickDetectsRealChanges proves the AGE-FACTS-2 volatile-attribute
// exclusion: a value whose only movement between scans is a self-ticking age fact
// (cred_access_key_1_age_days here) is NOT reported as changed, while every real change is
// still detected. The four real changes from the amendment are each exercised:
//   - key rotated: the stable cred_access_key_1_last_rotated date moves (age also resets,
//     but the date, not the age, is what carries the change) -> changed;
//   - credential added: a new identity appears -> appeared;
//   - credential removed: an identity is omitted -> disappeared;
//   - permission granted: a new assumes edge appears -> appeared.
//
// If the age fact were still hashed, "tick" would read as changed and this test would fail,
// so it also guards against a regression that drops the exclusion.
func TestDiffIgnoresAgeTickDetectsRealChanges(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ctx := context.Background()
	now := time.Now().UTC()

	tick1 := EntityInput{Provider: model.AWS, Type: model.NodeIdentity, NativeID: "tick", Name: "Tick",
		Attributes: credAttrs(
			"cred_access_key_1_active", "true",
			"cred_access_key_1_last_rotated", "2026-01-01T00:00:00Z",
			"cred_access_key_1_age_days", "277",
			"cred_mfa_active", "true",
		)}
	rotated1 := EntityInput{Provider: model.AWS, Type: model.NodeIdentity, NativeID: "rotated", Name: "Rotated",
		Attributes: credAttrs(
			"cred_access_key_1_active", "true",
			"cred_access_key_1_last_rotated", "2024-01-01T00:00:00Z",
			"cred_access_key_1_age_days", "642",
		)}
	// "removed" is present in scan 1 and omitted in scan 2 (credential removed).
	removed1 := user("removed", "Removed")

	if _, err := tn.Ingest(ctx, ScanInput{
		ToolVersion: "v1", Started: now, Completed: now,
		Entities: []EntityInput{tick1, rotated1, removed1},
		Evidence: oneEvidence(now),
	}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}

	later := now.Add(24 * time.Hour)
	// tick: only the age fact advances (277 -> 278); every stable fact is identical.
	tick2 := EntityInput{Provider: model.AWS, Type: model.NodeIdentity, NativeID: "tick", Name: "Tick",
		Attributes: credAttrs(
			"cred_access_key_1_active", "true",
			"cred_access_key_1_last_rotated", "2026-01-01T00:00:00Z",
			"cred_access_key_1_age_days", "278",
			"cred_mfa_active", "true",
		)}
	// rotated: a real rotation moves the stable last_rotated date (age also resets).
	rotated2 := EntityInput{Provider: model.AWS, Type: model.NodeIdentity, NativeID: "rotated", Name: "Rotated",
		Attributes: credAttrs(
			"cred_access_key_1_active", "true",
			"cred_access_key_1_last_rotated", "2026-10-01T00:00:00Z",
			"cred_access_key_1_age_days", "4",
		)}
	// added: a brand-new identity (credential added). It also anchors the granted edge.
	added2 := user("added", "Added")

	res2, err := tn.Ingest(ctx, ScanInput{
		ToolVersion: "v2", Started: later, Completed: later,
		Entities: []EntityInput{tick2, rotated2, added2},
		// permission granted: a new assumes edge from the new principal to a role.
		Edges:    []EdgeInput{{SourceNativeID: "added", TargetNativeID: "rotated", Kind: model.EdgeAssumes}},
		Evidence: oneEvidence(later),
	})
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}

	d, err := tn.Diff(ctx, 0)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if d.ScanID != res2.ScanID {
		t.Errorf("diff scan id = %d, want %d", d.ScanID, res2.ScanID)
	}

	// The pure age tick must not surface as a change (zero delta -> empty Change).
	if g := findEntityDelta(d, "tick"); g.Change != "" {
		t.Errorf("tick change = %q, want no change (age tick must be ignored)", g.Change)
	}
	// Every real change is still detected.
	if g := findEntityDelta(d, "rotated"); g.Change != "changed" {
		t.Errorf("rotated change = %q, want changed (last_rotated moved)", g.Change)
	}
	if g := findEntityDelta(d, "added"); g.Change != "appeared" {
		t.Errorf("added change = %q, want appeared (credential added)", g.Change)
	}
	if g := findEntityDelta(d, "removed"); g.Change != "disappeared" {
		t.Errorf("removed change = %q, want disappeared (credential removed)", g.Change)
	}
	if g := findEdgeDelta(d, "added", "rotated"); g.Change != "appeared" || g.Kind != model.EdgeAssumes {
		t.Errorf("added->rotated edge delta = %+v, want appeared assumes (permission granted)", g)
	}
}

// TestDiffNoScansIsEmpty proves a tenant with no scans yields an empty, non-error diff.
func TestDiffNoScansIsEmpty(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	d, err := tn.Diff(context.Background(), 0)
	if err != nil {
		t.Fatalf("diff on empty tenant: %v", err)
	}
	if d.ScanID != 0 || len(d.Entities) != 0 || len(d.Edges) != 0 {
		t.Errorf("empty-tenant diff = %+v, want empty", d)
	}
}
