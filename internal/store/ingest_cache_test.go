package store

import (
	"context"
	"database/sql"
	"testing"
)

// The initial load runs with the bulk-load page cache, and the load itself
// refuses to run without it (writeFirstScan checks). This test covers the
// rest: the connection's page cache is back as it was afterwards, after a
// successful load and after a refused one.
func TestFirstScanRestoresThePageCache(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	size := func() int64 {
		t.Helper()
		var n int64
		if err := tn.withConn(ctx, func(c *sql.Conn) error { return c.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&n) }); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := size()
	if before == -bulkLoadCacheKiB {
		t.Fatal("the default page cache is already the bulk-load size, so this test proves nothing")
	}
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 50, 3, 5, 1)); err != nil {
		t.Fatal(err)
	}
	if after := size(); after != before {
		t.Errorf("after the load the page cache is %d, want %d", after, before)
	}
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 5, 1, 1, 1)); err == nil {
		t.Fatal("a second initial load was accepted")
	}
	if after := size(); after != before {
		t.Errorf("after a refused load the page cache is %d, want %d", after, before)
	}
}
