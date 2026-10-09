package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"
)

// scanInput is a scan's objects for a test, before it is turned into a first or
// a later scan.
type scanInput struct {
	entities    []entityRecord
	edges       []edgeRecord
	evidence    []evidenceRecord
	permissions []permissionRecord
	exposures   []exposureRecord
	labels      []labelRecord
}

func awsRole(native, name string) entityRecord {
	p, _ := providerCodes.code("aws")
	nt, _ := nodeTypeCodes.code("role")
	return entityRecord{nativeID: native, name: name, provider: p, nodeType: nt}
}

func assumesEdge(src, dst int, confidence int64) edgeRecord {
	k, _ := edgeKindCodes.code("assumes")
	return edgeRecord{src: src, dst: dst, kind: k, confidence: confidence, evidence: 0}
}

var testScanAt = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

func (in scanInput) evidenceOrDefault() []evidenceRecord {
	if in.evidence != nil {
		return in.evidence
	}
	// One value-less evidence row, so an edge can cite evidence 0 and the scan
	// seals nothing but its manifest.
	return []evidenceRecord{{collector: "c", api: "a", observed: testScanAt}}
}

func loadFirst(t *testing.T, tn *Tenant, in scanInput) {
	t.Helper()
	_, err := tn.loadFirstScan(context.Background(), firstScan{
		toolVersion: "t", manifest: []byte("first"), started: testScanAt, completed: testScanAt,
		evidence: in.evidenceOrDefault(), entities: in.entities, edges: slices.Values(in.edges),
		permissions: in.permissions, exposures: in.exposures, labels: in.labels,
	})
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
}

func ingestLater(t *testing.T, tn *Tenant, in scanInput) {
	t.Helper()
	if _, err := tn.ingestScan(context.Background(), laterScanOf(in)); err != nil {
		t.Fatalf("later scan: %v", err)
	}
}

func laterScanOf(in scanInput) laterScan {
	return laterScan{
		toolVersion: "t", manifest: []byte("later"), started: testScanAt, completed: testScanAt,
		evidence: in.evidenceOrDefault(), entities: in.entities, edges: in.edges,
		permissions: in.permissions, exposures: in.exposures, labels: in.labels,
	}
}

func awsPerm(principal, resource int, action string, effect int64) permissionRecord {
	return permissionRecord{principal: principal, resource: resource, action: action, effect: effect, inheritedFrom: -1}
}

func awsExposure(node int, effective int64) exposureRecord {
	return exposureRecord{node: node, sourceZone: 1, protocol: 6, portFrom: 443, portTo: 443, authRequired: 1, effective: effective}
}

func awsLabel(entity int, label string, confidence int64) labelRecord {
	return labelRecord{entity: entity, label: label, method: "tag", confidence: confidence}
}

// entityByNative reads an entity's change-detection columns by its native ID.
type entityView struct {
	content  []byte
	gone     sql.NullInt64
	lastSeen int64
	found    bool
}

func entityByNative(t *testing.T, tn *Tenant, native string) entityView {
	t.Helper()
	sidHex, err := tn.StableID(native)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := hex.DecodeString(sidHex)
	if err != nil {
		t.Fatal(err)
	}
	var v entityView
	err = tn.withConn(context.Background(), func(c *sql.Conn) error {
		e := c.QueryRowContext(context.Background(),
			"SELECT content_hash, gone_scan, last_seen_scan FROM entities WHERE stable_id = ?", sid).
			Scan(&v.content, &v.gone, &v.lastSeen)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		v.found = e == nil
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func rowCount(t *testing.T, tn *Tenant, query string, args ...any) int64 {
	t.Helper()
	var n int64
	err := tn.withConn(context.Background(), func(c *sql.Conn) error {
		return c.QueryRowContext(context.Background(), query, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// snapshots counts entity_snapshots of one change kind.
func entitySnapshots(t *testing.T, tn *Tenant, change string) int64 {
	t.Helper()
	c, _ := changeCodes.code(change)
	return rowCount(t, tn, "SELECT count(*) FROM entity_snapshots WHERE change = ?", c)
}

func edgeSnapshots(t *testing.T, tn *Tenant, change string) int64 {
	t.Helper()
	c, _ := changeCodes.code(change)
	return rowCount(t, tn, "SELECT count(*) FROM edge_snapshots WHERE change = ?", c)
}

// scanNumber returns the nth scan_id in order, so tests can name the scan a
// row should point at.
func scanNumbers(t *testing.T, tn *Tenant) []int64 {
	t.Helper()
	var ids []int64
	err := tn.withConn(context.Background(), func(c *sql.Conn) error {
		rows, err := c.QueryContext(context.Background(), "SELECT scan_id FROM scans ORDER BY scan_id")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

const (
	roleA = "arn:aws:iam::111111111111:role/a"
	roleB = "arn:aws:iam::111111111111:role/b"
	roleC = "arn:aws:iam::111111111111:role/c"
	roleD = "arn:aws:iam::111111111111:role/d"
)

// A later scan classifies each entity as appeared, changed, unchanged, or
// disappeared, writing a change record for the first, second, and fourth, and
// only bumping last_seen for the third (ADR-0011 §1).
func TestLaterScanClassifiesChanges(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{
		awsRole(roleA, "a"), awsRole(roleB, "b"), awsRole(roleC, "c"),
	}})
	beforeB := entityByNative(t, tn, roleB).content

	// A unchanged, B renamed, C gone, D new.
	ingestLater(t, tn, scanInput{entities: []entityRecord{
		awsRole(roleA, "a"), awsRole(roleB, "b2"), awsRole(roleD, "d"),
	}})

	scans := scanNumbers(t, tn)
	if len(scans) != 2 {
		t.Fatalf("want 2 scans, got %d", len(scans))
	}
	first, second := scans[0], scans[1]

	if got := entitySnapshots(t, tn, "appeared"); got != 1 {
		t.Errorf("appeared records = %d, want 1 (D)", got)
	}
	if got := entitySnapshots(t, tn, "changed"); got != 1 {
		t.Errorf("changed records = %d, want 1 (B)", got)
	}
	if got := entitySnapshots(t, tn, "disappeared"); got != 1 {
		t.Errorf("disappeared records = %d, want 1 (C)", got)
	}

	a := entityByNative(t, tn, roleA)
	if a.gone.Valid || a.lastSeen != second {
		t.Errorf("A: gone=%v lastSeen=%d, want live and last seen in scan %d", a.gone, a.lastSeen, second)
	}
	b := entityByNative(t, tn, roleB)
	if bytes.Equal(b.content, beforeB) || b.lastSeen != second {
		t.Errorf("B: content unchanged or not re-seen (lastSeen=%d, want %d)", b.lastSeen, second)
	}
	c := entityByNative(t, tn, roleC)
	if !c.gone.Valid || c.gone.Int64 != second || c.lastSeen != first {
		t.Errorf("C: gone=%v lastSeen=%d, want gone in scan %d and last seen in scan %d", c.gone, c.lastSeen, second, first)
	}
	d := entityByNative(t, tn, roleD)
	if !d.found || d.gone.Valid || d.lastSeen != second {
		t.Errorf("D: found=%v gone=%v lastSeen=%d, want new and live in scan %d", d.found, d.gone, d.lastSeen, second)
	}
}

// A disappeared entity is soft-marked and kept; a disappeared edge's row is
// deleted, its change record kept.
func TestDisappearedEntitySoftMarkedEdgeDeleted(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{
		entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")},
		edges:    []edgeRecord{assumesEdge(0, 1, 50)},
	})
	if got := rowCount(t, tn, "SELECT count(*) FROM edges"); got != 1 {
		t.Fatalf("first scan wrote %d edges, want 1", got)
	}

	// Both entities remain, but the edge is not observed again.
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})

	if got := rowCount(t, tn, "SELECT count(*) FROM entities"); got != 2 {
		t.Errorf("entities = %d, want both kept", got)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM edges"); got != 0 {
		t.Errorf("edges = %d, want the disappeared edge deleted", got)
	}
	if got := edgeSnapshots(t, tn, "disappeared"); got != 1 {
		t.Errorf("edge disappeared records = %d, want 1", got)
	}
}

// A returning entity reappears against its existing row rather than inserting a
// duplicate identity, and records an appeared change.
func TestReappearedEntityRevivesExistingRow(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a")}})                      // B disappears
	ingestLater(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}}) // B returns

	if got := rowCount(t, tn, "SELECT count(*) FROM entities WHERE stable_id = ?", mustStableID(t, tn, roleB)); got != 1 {
		t.Errorf("B has %d rows, want exactly 1 (revived, not duplicated)", got)
	}
	if b := entityByNative(t, tn, roleB); b.gone.Valid {
		t.Errorf("B still marked gone after returning: %v", b.gone)
	}
	if got := entitySnapshots(t, tn, "appeared"); got != 1 {
		t.Errorf("appeared records = %d, want 1 (B's return)", got)
	}
	if got := entitySnapshots(t, tn, "disappeared"); got != 1 {
		t.Errorf("disappeared records = %d, want 1 (B's departure)", got)
	}
}

func mustStableID(t *testing.T, tn *Tenant, native string) []byte {
	t.Helper()
	h, err := tn.StableID(native)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An edge's last_seen_scan advances when its content changes but not when it is
// merely observed unchanged: edges are deleted on disappearance, so presence is
// the row's existence and there is no per-scan bump (the B-4 optimization).
func TestEdgeLastSeenTracksContentNotPresence(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ents := []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b"), awsRole(roleC, "c")}
	e0, e1 := assumesEdge(0, 1, 50), assumesEdge(0, 2, 50)
	loadFirst(t, tn, scanInput{entities: ents, edges: []edgeRecord{e0, e1}})

	e0changed := assumesEdge(0, 1, 60) // confidence changes
	ingestLater(t, tn, scanInput{entities: ents, edges: []edgeRecord{e0changed, e1}})

	scans := scanNumbers(t, tn)
	first, second := scans[0], scans[1]
	rows := edgeSeenScans(t, tn)
	if len(rows) != 2 {
		t.Fatalf("want 2 edges, got %d", len(rows))
	}
	// Ordered by edge_id: the changed edge advances, the unchanged one does not.
	if rows[0] != second {
		t.Errorf("changed edge last_seen = %d, want the later scan %d", rows[0], second)
	}
	if rows[1] != first {
		t.Errorf("unchanged edge last_seen = %d, want the first scan %d (no per-scan bump)", rows[1], first)
	}
}

func edgeSeenScans(t *testing.T, tn *Tenant) []int64 {
	t.Helper()
	var out []int64
	err := tn.withConn(context.Background(), func(c *sql.Conn) error {
		rows, err := c.QueryContext(context.Background(), "SELECT last_seen_scan FROM edges ORDER BY edge_id")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var v int64
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An identical rescan writes no change records and re-seals nothing: its only
// encryption is the new scan's own manifest.
func TestIdenticalRescanWritesNoChangeRecords(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	in := scanInput{
		entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")},
		edges:    []edgeRecord{assumesEdge(0, 1, 50)},
	}
	loadFirst(t, tn, in)
	before := sealCountNow(t, tn)

	ingestLater(t, tn, in)

	for _, k := range []string{"appeared", "changed", "disappeared"} {
		if got := entitySnapshots(t, tn, k); got != 0 {
			t.Errorf("entity %s records = %d, want 0", k, got)
		}
		if got := edgeSnapshots(t, tn, k); got != 0 {
			t.Errorf("edge %s records = %d, want 0", k, got)
		}
	}
	// Only the scan manifest sealed (the evidence has no value).
	if got := sealCountNow(t, tn) - before; got != 1 {
		t.Errorf("an identical rescan sealed %d values, want only the manifest (1)", got)
	}
}

// The entity content hash covers tags and attributes (B-1's entity twin): a
// change in either is detected, and undetected without the coverage.
func TestEntityHashCoversTagsAndAttributes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*entityRecord)
	}{
		{"tags", func(e *entityRecord) { e.tags = map[string]string{"env": "prod"} }},
		{"attributes", func(e *entityRecord) { e.attributes = map[string]string{"mfa": "on"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			tn := acquire(t, s, createTenant(t, s))
			base := awsRole(roleA, "a")
			loadFirst(t, tn, scanInput{entities: []entityRecord{base}})

			mutated := awsRole(roleA, "a")
			tc.mutate(&mutated)
			ingestLater(t, tn, scanInput{entities: []entityRecord{mutated}})

			if got := entitySnapshots(t, tn, "changed"); got != 1 {
				t.Errorf("changed records = %d, want 1: a %s change went undetected", got, tc.name)
			}
		})
	}
}

// The edge content hash covers the conditions (B-1): a conditions-only change
// is detected.
func TestEdgeHashCoversConditions(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ents := []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}
	e1 := assumesEdge(0, 1, 50)
	e1.conditions = map[string]string{"aws:SourceIp": "10.0.0.0/8"}
	loadFirst(t, tn, scanInput{entities: ents, edges: []edgeRecord{e1}})

	e2 := assumesEdge(0, 1, 50) // same confidence, different conditions
	e2.conditions = map[string]string{"aws:SourceIp": "0.0.0.0/0"}
	ingestLater(t, tn, scanInput{entities: ents, edges: []edgeRecord{e2}})

	if got := edgeSnapshots(t, tn, "changed"); got != 1 {
		t.Errorf("edge changed records = %d, want 1: a conditions-only change went undetected", got)
	}
}

// A content hash depends only on a map's contents, not its iteration order, so
// re-observing the same tags in another order is not a change.
func TestContentHashIgnoresMapOrder(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	first := awsRole(roleA, "a")
	first.tags = map[string]string{"a": "1", "b": "2", "c": "3"}
	loadFirst(t, tn, scanInput{entities: []entityRecord{first}})

	same := awsRole(roleA, "a")
	same.tags = map[string]string{"c": "3", "a": "1", "b": "2"} // same content
	ingestLater(t, tn, scanInput{entities: []entityRecord{same}})

	if got := entitySnapshots(t, tn, "changed"); got != 0 {
		t.Errorf("changed records = %d, want 0: map order was treated as a change", got)
	}
}

// The reservation is exactly the seals the apply performs: the count rises by
// the manifest plus each re-sealed field, and no more.
func TestLaterScanReservationIsExact(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
	before := sealCountNow(t, tn) // 0: the first scan is not yet counted

	// One entity changes its name (1 seal) plus one appeared entity (native +
	// name = 2 seals); the manifest is one more. Evidence has no value.
	ingestLater(t, tn, scanInput{entities: []entityRecord{
		awsRole(roleA, "a2"), awsRole(roleB, "b"), awsRole(roleC, "c"),
	}})
	if got := sealCountNow(t, tn) - before; got != 1+1+2 {
		t.Errorf("reservation drew %d seals, want 4 (manifest + renamed name + appeared native+name)", got)
	}
}

// A reservation short by one rolls the whole scan back before an unaccounted
// encryption: the scan does not land, current state is untouched, and the
// forfeited slot stays counted (fail-closed, B-6).
func TestLaterScanUnderCountRollsBackCleanly(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	ctx := context.Background()
	loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
	beforeA := entityByNative(t, tn, roleA).content
	beforeCount := sealCountNow(t, tn)

	in := scanInput{entities: []entityRecord{awsRole(roleA, "a2"), awsRole(roleB, "b")}}
	plan, err := tn.planLaterScan(ctx, laterScanOf(in))
	if err != nil {
		t.Fatal(err)
	}
	res, err := tn.reserveSeals(ctx, plan.seals-1) // one short
	if err != nil {
		t.Fatal(err)
	}
	_, err = tn.applyLaterScan(ctx, laterScanOf(in), plan, res)
	if !errors.Is(err, ErrKeyExhausted) {
		t.Fatalf("apply with a short reservation = %v, want ErrKeyExhausted", err)
	}
	if got := rowCount(t, tn, "SELECT count(*) FROM scans"); got != 1 {
		t.Errorf("a rolled-back later scan left %d scans, want 1", got)
	}
	if got := entitySnapshots(t, tn, "changed"); got != 0 {
		t.Errorf("a rolled-back later scan left %d change records", got)
	}
	if a := entityByNative(t, tn, roleA); !bytes.Equal(a.content, beforeA) {
		t.Error("a rolled-back later scan changed A's content")
	}
	// The short reservation committed and is not given back.
	if got := sealCountNow(t, tn); got != beforeCount+plan.seals-1 {
		t.Errorf("count = %d, want the forfeited reservation %d", got, beforeCount+plan.seals-1)
	}
}

// A later scan with a malformed record is rejected in the diff pass, before
// anything is reserved or written: nothing lands and no slots are spent.
func TestLaterScanRejectsBadRecords(t *testing.T) {
	badKind, _ := edgeKindCodes.code("assumes")
	for _, tc := range []struct {
		name string
		in   scanInput
	}{
		{"unknown provider", scanInput{entities: []entityRecord{{nativeID: roleC, name: "c", provider: 99, nodeType: 8}}}},
		{"duplicate identity", scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleA, "again")}}},
		{"edge kind not a code", scanInput{
			entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")},
			edges:    []edgeRecord{{src: 0, dst: 1, kind: 999, confidence: 50, evidence: 0}},
		}},
		{"edge evidence out of range", scanInput{
			entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")},
			edges:    []edgeRecord{{src: 0, dst: 1, kind: badKind, confidence: 50, evidence: 7}},
		}},
		{"edge endpoint out of range", scanInput{
			entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")},
			edges:    []edgeRecord{{src: 0, dst: 5, kind: badKind, confidence: 50, evidence: 0}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			tn := acquire(t, s, createTenant(t, s))
			loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
			before := sealCountNow(t, tn)

			if _, err := tn.ingestScan(context.Background(), laterScanOf(tc.in)); err == nil {
				t.Fatal("a malformed later scan was accepted")
			}
			if got := rowCount(t, tn, "SELECT count(*) FROM scans"); got != 1 {
				t.Errorf("a rejected later scan left %d scans, want 1", got)
			}
			if got := sealCountNow(t, tn); got != before {
				t.Errorf("a rejected later scan reserved %d slots, want none", got-before)
			}
		})
	}
}

// A process death after the reservation commits but before the apply lands
// leaves no scan and forfeits the slots, never reclaiming them (B-6). This is
// the ingest-level form of TestSealCountSurvivesRestartAndIsNeverReclaimed.
func TestLaterScanCrashAfterReserveLeavesNoScan(t *testing.T) {
	ctx := context.Background()
	opts := Options{DataDir: testDataDir(t), Keys: staticKeys(t, testMasterKey(t, 1))}

	in := scanInput{entities: []entityRecord{awsRole(roleA, "a2"), awsRole(roleB, "b"), awsRole(roleC, "c")}}
	var id TenantID
	var base, reserved int64 // base: the first scan's own (counted) seals
	func() {
		s := openStore(t, opts)
		id = createTenant(t, s)
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		loadFirst(t, tn, scanInput{entities: []entityRecord{awsRole(roleA, "a"), awsRole(roleB, "b")}})
		base = sealCountNow(t, tn)
		// Diff and reserve, then "crash": never apply.
		plan, err := tn.planLaterScan(ctx, laterScanOf(in))
		if err != nil {
			t.Fatal(err)
		}
		reserved = plan.seals
		if _, err := tn.reserveSeals(ctx, plan.seals); err != nil {
			t.Fatal(err)
		}
		release()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Restart: a fresh Store over the same files.
	s2 := openStore(t, opts)
	tn2 := acquire(t, s2, id)
	if got := rowCount(t, tn2, "SELECT count(*) FROM scans"); got != 1 {
		t.Errorf("after the crash there are %d scans, want only the first (the later scan never landed)", got)
	}
	if got := sealCountNow(t, tn2); got != base+reserved {
		t.Errorf("count = %d after the crash, want the first scan plus the forfeited reservation %d (not reclaimed)", got, base+reserved)
	}
	// A fresh retry succeeds and draws a new reservation on top of the forfeit.
	ingestLater(t, tn2, in)
	if got := rowCount(t, tn2, "SELECT count(*) FROM scans"); got != 2 {
		t.Errorf("after the retry there are %d scans, want 2", got)
	}
	if got := sealCountNow(t, tn2); got != base+reserved*2 {
		t.Errorf("count = %d after the retry, want %d (first scan + forfeited + the retry's own)", got, base+reserved*2)
	}
}
