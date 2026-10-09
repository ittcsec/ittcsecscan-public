package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// splitmix is SplitMix64, a small deterministic generator for fixtures.
type splitmix uint64

func (s *splitmix) next() uint64 {
	*s += 0x9e3779b97f4a7c15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// below returns a number in [0, n).
func (s *splitmix) below(n int) int { return int(s.next() % uint64(n)) } //nolint:gosec // G115: the result is below n, an int

// syntheticScan generates a deterministic first scan for the scale profiles
// of ADR-0011 §4: n entities, perEntity edges out of each to distinct
// (kind, target) pairs, a label on every labelEvery-th entity, and one piece
// of evidence per 100 entities. The edges are generated as they are read, so
// even 5,000,000 of them take no memory.
func syntheticScan(t *testing.T, n, perEntity, labelEvery int, seed uint64) firstScan {
	t.Helper()
	at := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	aws, role := mustCode(t, providerCodes, "aws"), mustCode(t, nodeTypeCodes, "role")
	s := firstScan{toolVersion: "synthetic", manifest: fmt.Appendf(nil, "synthetic %d", n), started: at, completed: at}
	for i := range n/100 + 1 {
		s.evidence = append(s.evidence, evidenceRecord{collector: "synthetic", api: "iam:ListRoles", observed: at, value: fmt.Appendf(nil, "page %d", i)})
	}
	s.entities = make([]entityRecord, n)
	for i := range n {
		s.entities[i] = entityRecord{nativeID: fmt.Sprintf("arn:aws:iam::%012d:role/r%d", 100000000000+i/1000, i), name: fmt.Sprintf("role-%d", i), provider: aws, nodeType: role}
	}
	for i := 0; i < n; i += labelEvery {
		s.labels = append(s.labels, labelRecord{entity: i, label: "crown-jewel", method: "synthetic", confidence: 90})
	}
	s.edges = func(yield func(edgeRecord) bool) {
		r := splitmix(seed)
		type pair struct {
			kind int64
			dst  int
		}
		picked := make([]pair, 0, perEntity)
		for src := range n {
			picked = picked[:0]
			for len(picked) < perEntity && n > 1 {
				p := pair{kind: int64(r.below(len(edgeKindCodes))) + 1, dst: r.below(n)}
				if p.dst != src && !slices.Contains(picked, p) {
					picked = append(picked, p)
				}
			}
			for _, p := range picked {
				if !yield(edgeRecord{src: src, dst: p.dst, kind: p.kind, confidence: 80, evidence: src / 100}) {
					return
				}
			}
		}
	}
	return s
}

func countRows(t *testing.T, tn *Tenant, table string) int {
	t.Helper()
	ctx := context.Background()
	var n int
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx, `SELECT count(*) FROM "`+table+`"`).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFirstScanLoadsEverything(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	scan := syntheticScan(t, 300, 10, 10, 7)
	scanID, err := tn.loadFirstScan(ctx, scan)
	if err != nil || scanID != 1 {
		t.Fatalf("loadFirstScan = %d, %v", scanID, err)
	}

	// The graph holds the edges written, in (kind, target) order per node.
	want := map[uint32][][2]int64{}
	for e := range scan.edges {
		src := uint32(e.src + 1) //nolint:gosec // G115: small test indexes
		want[src] = append(want[src], [2]int64{e.kind, int64(e.dst) + 1})
	}
	g, err := tn.loadGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if g.edgeCount() != 3000 {
		t.Errorf("graph has %d edges, want 3000", g.edgeCount())
	}
	for n := uint32(1); n <= 300; n++ {
		targets, kinds := g.out(n)
		var got [][2]int64
		for i := range targets {
			got = append(got, [2]int64{int64(kinds[i]), int64(targets[i])})
		}
		w := slices.Clone(want[n])
		slices.SortFunc(w, func(a, b [2]int64) int { return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1])) })
		if !slices.Equal(got, w) {
			t.Fatalf("node %d: out-edges %v, want %v", n, got, w)
		}
	}
	if len(g.labels) != 30 || !slices.Equal(g.labels[1], []string{"crown-jewel"}) || g.labels[2] != nil {
		t.Errorf("labels: %d nodes, node 1 %q, node 2 %q", len(g.labels), g.labels[1], g.labels[2])
	}

	// Entities hold their stable ID, and their sealed values open.
	err = tn.withConn(ctx, func(c *sql.Conn) error {
		var sid, native, name []byte
		if err := c.QueryRowContext(ctx, "SELECT stable_id, native_id_sealed, name_sealed FROM entities WHERE node_id = 42").Scan(&sid, &native, &name); err != nil {
			return err
		}
		want, _ := tn.StableID(scan.entities[41].nativeID)
		gotNative, err1 := tn.OpenValue(FieldEntityNativeID(), 42, native)
		gotName, err2 := tn.OpenValue(FieldEntityName(), 42, name)
		if hex.EncodeToString(sid) != want || string(gotNative) != scan.entities[41].nativeID || string(gotName) != "role-41" || err1 != nil || err2 != nil {
			return fmt.Errorf("entity 42: stable ID %x, native %q, name %q (%w)", sid, gotNative, gotName, errors.Join(err1, err2))
		}
		var stats int
		if err := c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_stat1 WHERE idx = 'edges_out'").Scan(&stats); err != nil || stats != 1 {
			return fmt.Errorf("statistics were not gathered after the load (%d, %w)", stats, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for table, n := range map[string]int{"scans": 1, "evidence": 4, "entities": 300, "edges": 3000, "classifications": 30} {
		if got := countRows(t, tn, table); got != n {
			t.Errorf("%s holds %d rows, want %d", table, got, n)
		}
	}

	// Only a tenant with no scans takes an initial load.
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 5, 1, 1, 1)); err == nil {
		t.Error("a second initial load was accepted")
	}
	if got := countRows(t, tn, "entities"); got != 300 {
		t.Errorf("the refused load changed the tenant: %d entities", got)
	}
}

func TestFirstScanWritesNothingWhenARecordIsInvalid(t *testing.T) {
	ctx := context.Background()
	for name, spoil := range map[string]func(*firstScan){
		"edge kind 0": func(s *firstScan) {
			s.edges = func(yield func(edgeRecord) bool) { yield(edgeRecord{src: 0, dst: 1, kind: 0}) }
		},
		"evidence out of range": func(s *firstScan) {
			s.edges = func(yield func(edgeRecord) bool) { yield(edgeRecord{src: 0, dst: 1, kind: 1, evidence: 9}) }
		},
		"edge to no entity": func(s *firstScan) {
			s.edges = func(yield func(edgeRecord) bool) { yield(edgeRecord{src: 0, dst: 99, kind: 1}) }
		},
		"label on no entity":  func(s *firstScan) { s.labels = []labelRecord{{entity: 99, label: "x", method: "x"}} },
		"provider 0":          func(s *firstScan) { s.entities[0].provider = 0 },
		"duplicate native ID": func(s *firstScan) { s.entities[1].nativeID = s.entities[0].nativeID },
		"confidence out of range": func(s *firstScan) {
			s.edges = func(yield func(edgeRecord) bool) { yield(edgeRecord{src: 0, dst: 1, kind: 1, confidence: 101}) }
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := newTestStore(t)
			tn := acquire(t, s, createTenant(t, s))
			scan := syntheticScan(t, 3, 1, 1, 1)
			spoil(&scan)
			if _, err := tn.loadFirstScan(ctx, scan); err == nil {
				t.Fatal("the invalid load was accepted")
			}
			for _, table := range []string{"scans", "evidence", "entities", "edges", "classifications"} {
				if n := countRows(t, tn, table); n != 0 {
					t.Errorf("%s holds %d rows after a refused load", table, n)
				}
			}
		})
	}
}

func TestGraphOfANewTenantIsEmpty(t *testing.T) {
	s, _ := newTestStore(t)
	g, err := acquire(t, s, createTenant(t, s)).loadGraph(context.Background())
	if err != nil || g.edgeCount() != 0 || len(g.labels) != 0 {
		t.Fatalf("empty graph: %v edges, %d labels, %v", g.edgeCount(), len(g.labels), err)
	}
}
