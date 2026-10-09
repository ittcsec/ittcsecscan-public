package store

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
)

// naturalKeys are the tables whose integer primary key is not a surrogate,
// so AUTOINCREMENT would add nothing.
var naturalKeys = map[string]string{
	"tenant":            "a single row, whose key is always 1",
	"schema_migrations": "the key is the migration's own number",
}

var (
	withoutRowID  = regexp.MustCompile(`(?i)\bWITHOUT\s+ROWID\b`)
	autoincrement = regexp.MustCompile(`(?i)\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b`)
)

// Surrogate keys are never reused (0002's header). A sealed value is bound to
// its row's key (ADR-0013), so a reused key could let a value open in a row it
// was never written to. Every rowid table therefore has a single INTEGER
// PRIMARY KEY with AUTOINCREMENT, except the natural keys above. A WITHOUT
// ROWID table has no single row key, so it may hold no sealed column.
func TestSurrogateKeysAreNeverReused(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		tables, err := userTables(ctx, c)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, table := range tables {
			seen[table] = true
			var text string
			if err := c.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", table).Scan(&text); err != nil {
				return err
			}
			if withoutRowID.MatchString(text) {
				var sealed int
				if err := c.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_xinfo(?) WHERE name LIKE '%\_sealed' ESCAPE '\'`, table).Scan(&sealed); err != nil {
					return err
				}
				if sealed != 0 {
					t.Errorf("%s is WITHOUT ROWID, so it has no single row key to bind its %d sealed columns to", table, sealed)
				}
				continue
			}
			if _, natural := naturalKeys[table]; natural {
				continue
			}
			var keys int
			var typ string
			if err := c.QueryRowContext(ctx, "SELECT count(*), max(type) FROM pragma_table_info(?) WHERE pk > 0", table).Scan(&keys, &typ); err != nil {
				return err
			}
			if keys != 1 || typ != "INTEGER" || !autoincrement.MatchString(text) {
				t.Errorf("%s does not have a single INTEGER PRIMARY KEY AUTOINCREMENT, so its keys could be reused", table)
			}
		}
		for table := range naturalKeys {
			if !seen[table] {
				t.Errorf("exempt table %s no longer exists: remove it from naturalKeys", table)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A completed scan has a completion time (owner decision, 2026-09-14).
func TestCompletedScansHaveACompletionTime(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	completed, running := mustCode(t, scanStatusCodes, "completed"), mustCode(t, scanStatusCodes, "running")
	for _, c := range []struct {
		status      int64
		completedAt any
		ok          bool
	}{
		{completed, nil, false},
		{completed, 1_000, true},
		{running, nil, true},
	} {
		err := tn.withConn(ctx, func(conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, `INSERT INTO scans (tenant_id, started_at, completed_at, tool_version, status, manifest_sealed, manifest_hash)
				VALUES (?, 0, ?, 'test', ?, x'00', zeroblob(32))`, tn.ID().String(), c.completedAt, c.status)
			return err
		})
		if (err == nil) != c.ok {
			t.Errorf("status %d, completed_at %v: error = %v, want accepted = %v", c.status, c.completedAt, err, c.ok)
		}
	}
}

// An edge may lead from an entity to itself: a role that trusts itself is a
// finding, not an error (owner decision, 2026-09-14).
func TestSelfLoopEdgesAreAllowed(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	trusts := mustCode(t, edgeKindCodes, "trusts")
	scan := syntheticScan(t, 3, 1, 1, 1)
	scan.edges = func(yield func(edgeRecord) bool) { yield(edgeRecord{src: 1, dst: 1, kind: trusts, confidence: 90}) }
	if _, err := tn.loadFirstScan(ctx, scan); err != nil {
		t.Fatalf("a self-loop edge was refused: %v", err)
	}
	g, err := tn.loadGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targets, kinds := g.out(2)
	if len(targets) != 1 || targets[0] != 2 || int64(kinds[0]) != trusts {
		t.Errorf("node 2's out-edges: %v %v, want itself by trusts", targets, kinds)
	}
}
