package store

import (
	"testing"
)

// A later scan diffs permissions, exposures, and classifications the same way
// as entities and edges: appeared rows are inserted, changed rows updated in
// place (same row ID), unchanged rows left alone, and disappeared rows deleted.
func TestLaterScanModelTableChangeDetection(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ents := []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}
	loadFirst(t, tn, scanInput{
		entities:    ents,
		permissions: []permissionRecord{awsPerm(0, 1, "s3:GetObject", 1)},
		exposures:   []exposureRecord{awsExposure(1, 1)},
		labels:      []labelRecord{awsLabel(0, "crown-jewel", 90)},
	})
	permID := rowCount(t, tn, "SELECT permission_id FROM permissions")
	expID := rowCount(t, tn, "SELECT exposure_id FROM exposures")

	// Later scan: permission unchanged; exposure's reachability flips (changed);
	// classification gone (not observed); a second permission appears.
	ingestLater(t, tn, scanInput{
		entities: ents,
		permissions: []permissionRecord{
			awsPerm(0, 1, "s3:GetObject", 1), // unchanged
			awsPerm(0, 1, "s3:PutObject", 1), // appeared
		},
		exposures: []exposureRecord{awsExposure(1, 2)}, // effective 1 -> 2
	})

	if got := rowCount(t, tn, "SELECT count(*) FROM permissions"); got != 2 {
		t.Errorf("permissions = %d, want 2 (unchanged kept + appeared)", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM permissions WHERE permission_id = ?", permID); got != 1 {
		t.Error("the unchanged permission's row was replaced, not kept")
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM exposures"); got != 1 {
		t.Errorf("exposures = %d, want 1 (changed in place)", got)
	}
	if got := rowCount(t, tn, "SELECT exposure_id FROM exposures"); got != expID {
		t.Error("the changed exposure was replaced, not updated in place")
	}
	if got := rowCount(t, tn, "SELECT effective FROM exposures WHERE exposure_id = ?", expID); got != 2 {
		t.Errorf("exposure effective = %d, want 2 (updated)", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM classifications"); got != 0 {
		t.Errorf("classifications = %d, want 0 (disappeared and deleted)", got)
	}
}

// A permission whose effect flips (allow to deny) is the same permission
// changed, not a new one: the identity is principal/resource/action, and the
// effect is content.
func TestPermissionEffectFlipIsAChange(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ents := []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}
	loadFirst(t, tn, scanInput{entities: ents, permissions: []permissionRecord{awsPerm(0, 1, "s3:GetObject", 1)}})
	id := rowCount(t, tn, "SELECT permission_id FROM permissions")

	ingestLater(t, tn, scanInput{entities: ents, permissions: []permissionRecord{awsPerm(0, 1, "s3:GetObject", 2)}}) // effect 1 -> 2

	if got := rowCount(t, tn, "SELECT count(*) FROM permissions"); got != 1 {
		t.Errorf("permissions = %d, want 1 (a flipped effect is a change, not a new row)", got)
	}
	if got := rowCount(t, tn, "SELECT permission_id FROM permissions"); got != id {
		t.Error("the permission was replaced, not updated in place")
	}
	if got := rowCount(t, tn, "SELECT effect FROM permissions"); got != 2 {
		t.Errorf("effect = %d, want 2", got)
	}
}

// A gone entity is kept while any record still refers to it, and removed once
// nothing does: its edges, permissions, and classifications have disappeared,
// and retention has pruned its change records.
func TestGoneEntityCollectedWhenUnreferenced(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	entsAB := []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}
	loadFirst(t, tn, scanInput{
		entities: entsAB,
		edges:    []edgeRecord{assumesEdge(0, 1, 50)},
		labels:   []labelRecord{awsLabel(0, "crown-jewel", 90)},
	})
	setRetention(t, tn, 1) // keep only the newest scan, so change records prune fast

	goneCount := func() int64 {
		return rowCount(t, tn, "SELECT count(*) FROM entities WHERE gone_scan IS NOT NULL")
	}
	entityCount := func() int64 { return rowCount(t, tn, "SELECT count(*) FROM entities") }

	// A disappears: its edge and classification go too, but its disappeared
	// change record still refers to it, so it is kept.
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleB, "b")}})
	if entityCount() != 2 || goneCount() != 1 {
		t.Fatalf("after A disappears: %d entities, %d gone; want 2 and 1 (A kept, referenced by its change record)", entityCount(), goneCount())
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM edges"); got != 0 {
		t.Errorf("edges = %d, want 0 (A's edge deleted)", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM classifications"); got != 0 {
		t.Errorf("classifications = %d, want 0 (A's classification deleted)", got)
	}

	// A further scan prunes A's change record; with nothing left referring to
	// it, A is collected.
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleB, "b")}})
	if entityCount() != 1 || goneCount() != 0 {
		t.Errorf("after retention prunes A's record: %d entities, %d gone; want 1 and 0 (A collected)", entityCount(), goneCount())
	}
	if got := entityByNative(t, tn, roleB); !got.found {
		t.Error("B (still present) was collected by mistake")
	}
}
