package store

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestIngestCancelDoesNotPoisonConnection is a best-effort guard that the
// cancelled-transaction fix also covers the ingest write path (loadFirstScan,
// which calls writeFirstScan in ingest.go). Like the other tenant operations it
// begins its transaction on the tenant's single shared connection, so a
// cancelled ingest must leave that connection reusable.
//
// Unlike Update, ingest takes scan data rather than a callback, so there is no
// seam to cancel at deterministically: the race lives in database/sql's
// asynchronous context-cancellation rollback timing. This cancels an ingest
// concurrently over several fresh tenants (a sizeable scan widens the
// transaction so the cancel can land inside it) and then reuses the connection,
// which must always be able to begin its own transaction. The deterministic
// red-without-fix proof is TestUpdateCancelDoesNotPoisonConnection; this extends
// coverage to the ingest path, which carries the identical WithoutCancel fix.
func TestIngestCancelDoesNotPoisonConnection(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	records := make([]entityRecord, 250)
	for i := range records {
		native := fmt.Sprintf("arn:aws:iam::000000000000:role/r%d", i)
		records[i] = entityRecord{
			nativeID: native, name: native,
			provider: fixtureProvider(t, native), nodeType: mustCode(t, nodeTypeCodes, "role"),
		}
	}
	scan := firstScan{
		toolVersion: "t", manifest: []byte("m"), started: at, completed: at,
		evidence: []evidenceRecord{{collector: "c", api: "a", observed: at}},
		entities: records,
	}
	for i := 0; i < 12; i++ {
		s, _ := newTestStore(t)
		tn := acquire(t, s, createTenant(t, s))
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			runtime.Gosched()
			cancel() // try to land inside the ingest transaction
		}()
		_, _ = tn.loadFirstScan(ctx, scan) // may commit or be cancelled; both are fine
		// Reuse the shared connection. Before the fix a cancelled ingest could
		// leave database/sql's async rollback in flight and fail this begin with
		// "cannot start a transaction within a transaction".
		if _, err := tn.Diff(context.Background(), 0); err != nil {
			t.Fatalf("iteration %d: reuse after cancelled ingest failed: %v", i, err)
		}
	}
}
