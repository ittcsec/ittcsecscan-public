package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// rawConn opens a tenant's file directly, outside the store, the way another
// process would. The caller closes it.
func rawConn(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// insertBareEntity writes one entity with the given tenant ID, filling every
// NOT NULL column with a placeholder. It is enough to change the row count.
func insertBareEntity(ctx context.Context, x interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenantID string) error {
	_, err := x.ExecContext(ctx, `INSERT INTO entities
		(tenant_id, stable_id, provider, type, native_id_sealed, content_hash, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		VALUES (?, randomblob(32), 1, 1, x'00', zeroblob(32), 1, 1, 0, 0)`, tenantID)
	return err
}

// The graph load reads in one transaction, so a commit by another connection
// between its reads is not seen: the graph is a single snapshot (ADR-0011 §4).
func TestGraphLoadUsesASnapshot(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	id := createTenant(t, s)
	tn, release, err := s.Acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 20, 2, 5, 1)); err != nil {
		t.Fatal(err)
	}
	release()
	path := dbPath(tenantDir(t, s, id))

	connA, connB := rawConn(t, path), rawConn(t, path)
	tx, err := connA.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	var before int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM entities").Scan(&before); err != nil {
		t.Fatal(err) // this first read fixes the snapshot
	}
	if err := insertBareEntity(ctx, connB, id.String()); err != nil {
		t.Fatal(err)
	}
	var seenByB int
	if err := connB.QueryRowContext(ctx, "SELECT count(*) FROM entities").Scan(&seenByB); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM entities").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if seenByB != before+1 {
		t.Errorf("the writing connection sees %d entities, want %d: the commit did not land", seenByB, before+1)
	}
	if after != before {
		t.Errorf("the read transaction saw the commit: %d entities, want its snapshot's %d", after, before)
	}
}

// loadGraph itself sees a single snapshot: a classification committed by
// another connection while loadGraph runs, after its edge read, is not in the
// result. The mid-read commit is driven through graphReadHook, so this
// exercises loadGraph's own transaction, not just SQLite's isolation.
func TestGraphLoadIgnoresCommitsMidRead(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	id := createTenant(t, s)
	tn, release, err := s.Acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 20, 2, 5, 1)); err != nil {
		t.Fatal(err)
	}
	connB := rawConn(t, dbPath(tenantDir(t, s, id)))

	var fired bool
	graphReadHook = func() {
		if fired {
			return
		}
		fired = true
		// A classification on node 2, which had none, committed from another
		// connection. A single-snapshot load must not see it.
		_, err := connB.ExecContext(ctx, `INSERT INTO classifications
			(tenant_id, classification_hash, node_id, label_sealed, method_sealed, confidence, content_hash, first_seen_scan, last_seen_scan)
			VALUES (?, randomblob(32), 2, x'00', x'00', 50, randomblob(32), 1, 1)`, id.String())
		if err != nil {
			t.Errorf("committing the mid-read classification: %v", err)
		}
	}
	t.Cleanup(func() { graphReadHook = nil })

	g, err := tn.loadGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Fatal("the mid-read hook never ran")
	}
	if len(g.labels) != 4 {
		t.Errorf("graph has labels on %d nodes, want 4: the mid-read commit leaked into the load", len(g.labels))
	}
	if g.labels[2] != nil {
		t.Errorf("node 2 got a label from the mid-read commit: %q", g.labels[2])
	}
	// The commit did land, for a connection that reads after it.
	var n int
	if err := connB.QueryRowContext(ctx, "SELECT count(*) FROM classifications").Scan(&n); err != nil || n != 5 {
		t.Errorf("classifications after the commit: %d (%v), want 5", n, err)
	}
}

// The index rebuild re-executes each stored index definition, then reads back
// what SQLite recorded and requires it to be byte-for-byte the same. A
// definition with a statement appended after the CREATE INDEX is refused, and
// the whole load being one transaction, the appended statement rolls back
// (threat T-29).
func TestIndexRebuildRefusesAppendedSQL(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		tx, err := c.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		good := &loadWriter{ctx: ctx, tx: tx}
		good.createIndexes([]bulkIndex{{name: "probe_ok", def: "CREATE INDEX probe_ok ON edges (confidence)"}})
		if good.err != nil {
			t.Errorf("a plain single-statement index was refused: %v", good.err)
		}

		bad := &loadWriter{ctx: ctx, tx: tx}
		bad.createIndexes([]bulkIndex{{name: "probe_evil", def: "CREATE INDEX probe_evil ON edges (kind); DROP TABLE entities"}})
		if !errors.Is(bad.err, ErrForeignFile) {
			t.Errorf("appended SQL: err = %v, want ErrForeignFile", bad.err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The appended DROP ran inside the rolled-back transaction, so entities
	// is intact; countRows would fail if the table were gone.
	if n := countRows(t, tn, "entities"); n != 0 {
		t.Errorf("entities holds %d rows after the rolled-back tamper", n)
	}
}

// A load cancelled midway writes nothing and restores the page cache, so the
// tenant is left exactly as it was.
func TestFirstScanCancelledMidwayIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))

	cacheSize := func() int64 {
		t.Helper()
		var n int64
		if err := tn.withConn(context.Background(), func(c *sql.Conn) error {
			return c.QueryRowContext(context.Background(), "PRAGMA cache_size").Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := cacheSize()

	scan := syntheticScan(t, 40, 3, 5, 1)
	orig := scan.edges
	scan.edges = func(yield func(edgeRecord) bool) {
		cancelled := false
		for e := range orig {
			if !cancelled { // cancel once the load is under way
				cancel()
				cancelled = true
			}
			if !yield(e) {
				return
			}
		}
	}
	// A cancelled load fails; it does not matter with which error. SQLite
	// interrupts the running statement, so the load surfaces either
	// context.Canceled (database/sql observed the cancellation) or the driver's
	// own interrupt error, and which one arrives is a race, especially under
	// the race detector. The contract this test guards is the all-or-nothing
	// one below, not the identity of the error.
	if _, err := tn.loadFirstScan(ctx, scan); err == nil {
		t.Fatal("a cancelled load was accepted")
	}
	for _, table := range []string{"scans", "evidence", "entities", "edges", "classifications"} {
		if n := countRows(t, tn, table); n != 0 {
			t.Errorf("%s holds %d rows after a cancelled load", table, n)
		}
	}
	if after := cacheSize(); after != before {
		t.Errorf("the page cache is %d after a cancelled load, want %d", after, before)
	}
}
