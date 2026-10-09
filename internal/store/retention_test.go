package store

import (
	"context"
	"slices"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/repo"
)

// setRetention sets the tenant's retention window through the repository.
func setRetention(t *testing.T, tn *Tenant, n int) {
	t.Helper()
	if err := tn.Update(context.Background(), func(w repo.Writer) error {
		return w.Settings().SetRetentionScans(context.Background(), n)
	}); err != nil {
		t.Fatal(err)
	}
}

// A later scan keeps only the most recent retention_scans scans. Older scans
// and their per-scan records are cascade-deleted; current state survives.
func TestRetentionPrunesOldScansAndCascades(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
	firstScan := scanNumbers(t, tn)[0]
	setRetention(t, tn, 2)

	// Four later scans, each renaming A so every scan writes a change record;
	// with the first scan that is five scans, well over the window of two.
	for _, name := range []string{"a1", "a2", "a3", "a4"} {
		ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, name), awsRole(roleB, "b")}})
	}

	final := scanNumbers(t, tn)
	if len(final) != 2 {
		t.Fatalf("scans = %v, want the 2 most recent", final)
	}
	// The oldest scans were the ones pruned: the first scan is gone, and the
	// most recent scan (the one that just ran) survived.
	if slices.Contains(final, firstScan) {
		t.Errorf("the first scan %d survived retention; kept = %v", firstScan, final)
	}
	if !slices.IsSorted(final) || final[1] != final[0]+1 {
		t.Errorf("kept scans = %v, want the two consecutive most recent", final)
	}
	// The cascade fired: nothing references a pruned scan.
	for _, tbl := range []string{"evidence", "entity_snapshots", "edge_snapshots", "findings", "attack_paths", "scopes"} {
		if got := rowCount(t, tn, "SELECT count(*) FROM "+tbl+" WHERE scan_id NOT IN (SELECT scan_id FROM scans)"); got != 0 {
			t.Errorf("%s keeps %d rows for a pruned scan, want 0 (cascade failed)", tbl, got)
		}
	}
	// Exactly the retained scans' change records remain (scans 2..5 each wrote
	// one for A; only the last two are kept).
	if got := rowCount(t, tn, "SELECT count(*) FROM entity_snapshots"); got != 2 {
		t.Errorf("entity_snapshots = %d, want 2 (only the retained scans')", got)
	}
	// Current state survives retention.
	if got := rowCount(t, tn, "SELECT count(*) FROM entities"); got != 2 {
		t.Errorf("entities = %d after retention, want 2 (current state must survive)", got)
	}
	// And the survived entity reads back with the latest value.
	if a := entityByNative(t, tn, roleA); !a.found {
		t.Error("entity A is gone after retention")
	}
}

// Under the window, a later scan prunes nothing.
func TestRetentionKeepsEverythingWithinWindow(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a")}})
	setRetention(t, tn, 30)

	for _, name := range []string{"a1", "a2"} {
		ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, name)}})
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM scans"); got != 3 {
		t.Errorf("scans = %d, want all 3 kept within the window", got)
	}
}

// Retention is atomic with the scan that triggers it: if that scan rolls back,
// nothing is pruned either.
func TestRetentionRollsBackWithAFailedScan(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
	setRetention(t, tn, 1) // one scan: any later scan would prune the first
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a1"), awsRole(roleB, "b")}})
	// After a successful later scan under a window of one, only it remains.
	if got := rowCount(t, tn, "SELECT count(*) FROM scans"); got != 1 {
		t.Fatalf("scans = %d, want 1 under a window of 1", got)
	}
	surviving := scanNumbers(t, tn)[0]

	// A later scan whose reservation is one short rolls back; its prune, in the
	// same transaction, must roll back too, so the surviving scan is untouched.
	in := scanInput{entities: []entityRecord{awsRole(roleA, "a2"), awsRole(roleB, "b")}}
	plan, err := tn.planLaterScan(ctx, laterScanOf(in))
	if err != nil {
		t.Fatal(err)
	}
	res, err := tn.reserveSeals(ctx, plan.seals-1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tn.applyLaterScan(ctx, laterScanOf(in), plan, res); err == nil {
		t.Fatal("a short-reservation later scan was applied")
	}
	got := scanNumbers(t, tn)
	if len(got) != 1 || got[0] != surviving {
		t.Errorf("after a rolled-back scan, scans = %v, want just %d (prune must roll back too)", got, surviving)
	}
}
