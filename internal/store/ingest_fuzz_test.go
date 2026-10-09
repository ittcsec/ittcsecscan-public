package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fuzzDataDir returns a private data directory whose path has no '#' or '?'.
// A fuzz subtest is named like "seed#7", so t.TempDir() would embed a '#',
// which the store rejects in a data-directory path.
func fuzzDataDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "ittcsecscan-fuzz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return filepath.Join(base, "data")
}

// FuzzFirstScanRejectsBadRecords drives the first-scan loader with arbitrary
// record fields and asserts its all-or-nothing contract: the load either
// succeeds with exactly the rows it was given, or fails and writes nothing. It
// must never panic and never leave a partial scan. This exercises the
// record-validation paths that the collectors will later feed with real
// provider data (threat T-16).
func FuzzFirstScanRejectsBadRecords(f *testing.F) {
	// entityCount, provider, nodeType, edgeKind, src, dst, confidence, evIdx, labelEntity
	f.Add(3, int64(1), int64(1), int64(1), 0, 1, int64(80), 0, 0)  // valid
	f.Add(0, int64(1), int64(1), int64(1), 0, 0, int64(0), 0, 0)   // no entities: the edge dangles
	f.Add(2, int64(99), int64(1), int64(1), 0, 1, int64(80), 0, 0) // provider not a code
	f.Add(2, int64(1), int64(1), int64(0), 0, 1, int64(80), 0, 0)  // edge kind 0
	f.Add(2, int64(1), int64(1), int64(1), 0, 9, int64(80), 0, 0)  // dst out of range
	f.Add(2, int64(1), int64(1), int64(1), 0, 1, int64(101), 0, 0) // confidence over 100
	f.Add(1, int64(1), int64(1), int64(1), 0, 0, int64(50), 1, 0)  // evidence index out of range
	f.Add(2, int64(1), int64(1), int64(1), 0, 1, int64(50), 0, 9)  // label on no entity
	f.Add(1, int64(1), int64(1), int64(1), 0, 0, int64(50), 0, 0)  // self-loop, allowed

	f.Fuzz(func(t *testing.T, entityCount int, provider, nodeType, edgeKind int64, src, dst int, confidence int64, evIdx, labelEntity int) {
		if entityCount < 0 || entityCount > 8 {
			return // keep each iteration small; the contract does not depend on size
		}
		ctx := context.Background()
		s := openStore(t, Options{DataDir: fuzzDataDir(t), Keys: staticKeys(t, testMasterKey(t, 1))})
		tn := acquire(t, s, createTenant(t, s))
		at := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

		scan := firstScan{
			toolVersion: "fuzz", manifest: []byte("fuzz"), started: at, completed: at,
			evidence: []evidenceRecord{{collector: "c", api: "a", observed: at}},
		}
		for i := 0; i < entityCount; i++ {
			scan.entities = append(scan.entities, entityRecord{
				nativeID: fmt.Sprintf("arn:%d", i), name: fmt.Sprintf("e%d", i),
				provider: provider, nodeType: nodeType,
			})
		}
		scan.edges = func(yield func(edgeRecord) bool) {
			yield(edgeRecord{src: src, dst: dst, kind: edgeKind, confidence: confidence, evidence: evIdx})
		}
		hasLabel := entityCount > 0
		if hasLabel {
			scan.labels = []labelRecord{{entity: labelEntity, label: "l", method: "m", confidence: 50}}
		}

		_, err := tn.loadFirstScan(ctx, scan)
		counts := map[string]int{}
		for _, table := range []string{"scans", "evidence", "entities", "edges", "classifications"} {
			counts[table] = countRows(t, tn, table)
		}
		if err != nil {
			for table, n := range counts {
				if n != 0 {
					t.Fatalf("a failed load left %d rows in %s (err %v)", n, table, err)
				}
			}
			return
		}
		// On success, exactly the records fed in are present: one scan, one
		// evidence row, every entity, the one edge, and the label if any.
		want := map[string]int{"scans": 1, "evidence": 1, "entities": entityCount, "edges": 1, "classifications": 0}
		if hasLabel {
			want["classifications"] = 1
		}
		for table, n := range want {
			if counts[table] != n {
				t.Fatalf("a successful load put %d rows in %s, want %d", counts[table], table, n)
			}
		}
	})
}
