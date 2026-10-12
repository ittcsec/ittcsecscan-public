package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// A later scan is a scan after a tenant's first. It is compared with the
// current state, and only the objects that appeared, changed, or disappeared
// are written, with a change record for each (ADR-0011 §1). Unchanged objects
// keep their rows and get their last_seen_scan bumped in one bulk statement, so
// the work and the encryptions are proportional to churn, not to the estate.
//
// The seals a later scan performs are counted and bounded (B-6): the diff pass
// computes the exact number, a reservation for exactly that many is committed
// before the apply transaction, and the apply draws one slot per encryption.
// Because the reservation commits first, a crash during apply forfeits the
// slots (a safe over-count) and never lets an encryption go uncounted.
type laterScan struct {
	toolVersion        string
	manifest           []byte
	started, completed time.Time
	evidence           []evidenceRecord
	entities           []entityRecord
	edges              []edgeRecord // endpoints and evidence are positions in this scan
	permissions        []permissionRecord
	exposures          []exposureRecord
	labels             []labelRecord // classifications
	scopes             []scopeRecord
}

// edgeKey is an edge's identity: its endpoints (by node ID) and its kind. Node
// IDs stay int64 because they are never reused and outgrow any narrower type
// over a long-lived tenant's history.
type edgeKey struct{ src, kind, dst int64 }

// entState and edgeState are a current-state row's identity-independent facts,
// held for the diff. The 32-byte content hash is kept whole: a disappeared
// object's change record repeats it.
type entState struct {
	nodeID int64
	hash   []byte
	gone   bool
}

type edgeState struct {
	edgeID int64
	hash   []byte
}

type entChange struct {
	pos    int
	nodeID int64
}

type edgeChange struct {
	pos    int
	edgeID int64
}

type entGone struct {
	nodeID int64
	hash   []byte
}

type edgeGone struct {
	edgeID         int64
	src, kind, dst int64
	hash           []byte
}

// laterPlan is the diff pass's decision, carried into the apply transaction. It
// holds one entry per changed object (proportional to churn); unchanged objects
// appear only as a bulk last_seen bump. seals is the exact number of
// encryptions the apply will perform.
type laterPlan struct {
	entAppeared   []int
	entChanged    []entChange
	entReappeared []entChange
	entGone       []entGone
	edgeAppeared  []int
	edgeChanged   []edgeChange
	edgeGone      []edgeGone
	// permissions, exposures, and classifications are current-state tables keyed
	// by an identity hash, with no history and no soft-gone: appeared inserts,
	// changed updates, unchanged does nothing, disappeared deletes. gone holds
	// the row IDs to delete.
	permAppeared, exposureAppeared, classAppeared []int
	permChanged, exposureChanged, classChanged    []rowChange
	permGone, exposureGone, classGone             []int64
	nodeByPos                                     []int64 // entity position -> existing node ID, 0 until an appeared entity is assigned one
	seals                                         int64
}

// rowChange names a changed current-state row: its position in the scan and the
// existing row ID to update.
type rowChange struct {
	pos int
	id  int64
}

// rowState is a current-state row's ID and content hash, for an identity-hashed
// table (permissions, exposures, classifications).
type rowState struct {
	id   int64
	hash []byte
}

// scanPhase, when non-nil (tests only), receives the wall time of each named
// phase of a later scan, so the scale benchmark can report where the time goes.
// It is nil in production.
var scanPhase func(name string, d time.Duration)

// phaseDo times fn under name when scanPhase is set, and just runs it otherwise.
func phaseDo(name string, fn func()) {
	if scanPhase == nil {
		fn()
		return
	}
	start := time.Now()
	fn()
	scanPhase(name, time.Since(start))
}

// ingestScan applies a later scan in three steps that never overlap on the
// tenant connection: diff (read only), reserve (its own committed transaction),
// apply (one atomic transaction). Splitting them keeps the reservation's commit
// ahead of the encryptions it authorises (B-6) and the whole scan atomic.
func (t *Tenant) ingestScan(ctx context.Context, s laterScan) (int64, error) {
	start := time.Now()
	plan, err := t.planLaterScan(ctx, s)
	if err != nil {
		return 0, err
	}
	if scanPhase != nil {
		scanPhase("diff", time.Since(start))
	}
	res, err := t.reserveSeals(ctx, plan.seals)
	if err != nil {
		return 0, err
	}
	start = time.Now()
	id, err := t.applyLaterScan(ctx, s, plan, res)
	if scanPhase != nil {
		scanPhase("apply", time.Since(start))
	}
	return id, err
}

// planLaterScan is the diff pass. It reads current state under one snapshot,
// classifies every observed object, and counts the seals the apply will need.
// It writes nothing and decrypts nothing: it compares content hashes, which are
// keyed hashes of plaintext, so an unchanged value is recognised without
// re-sealing it.
func (t *Tenant) planLaterScan(ctx context.Context, s laterScan) (*laterPlan, error) {
	p := &laterPlan{nodeByPos: make([]int64, len(s.entities))}
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) error {
			// Non-cancellable to avoid the shared-connection rollback race; see
			// the comment on BeginTx in (*Tenant).View (repo.go).
			tx, err := c.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback() }()
			ents, err := loadEntityState(ctx, tx)
			if err != nil {
				return err
			}
			edgesCur, err := loadEdgeState(ctx, tx)
			if err != nil {
				return err
			}
			permCur, err := loadRowState(ctx, tx, "permissions", "permission_hash", "permission_id")
			if err != nil {
				return err
			}
			expCur, err := loadRowState(ctx, tx, "exposures", "exposure_hash", "exposure_id")
			if err != nil {
				return err
			}
			classCur, err := loadRowState(ctx, tx, "classifications", "classification_hash", "classification_id")
			if err != nil {
				return err
			}
			seals := int64(1) // the scan manifest
			for i := range s.evidence {
				if s.evidence[i].value != nil {
					seals++
				}
			}
			for i := range s.scopes {
				seals++ // scope account, always sealed
				if s.scopes[i].region != "" {
					seals++ // scope region, sealed when present
				}
			}
			counts := make([]int64, 0, 5)
			for _, classify := range []func() (int64, error){
				func() (int64, error) { return p.classifyEntities(k, s.entities, ents) },
				func() (int64, error) { return p.classifyEdges(k, s.edges, s.evidence, edgesCur) },
				func() (int64, error) { return p.classifyPermissions(k, s.permissions, s.entities, permCur) },
				func() (int64, error) { return p.classifyExposures(k, s.exposures, s.entities, expCur) },
				func() (int64, error) { return p.classifyClassifications(k, s.labels, s.entities, classCur) },
			} {
				n, err := classify()
				if err != nil {
					return err
				}
				counts = append(counts, n)
			}
			for _, n := range counts {
				seals += n
			}
			p.seals = seals
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// classifyEntities decides each observed entity and returns the seals its
// apply will perform. It deletes matched identities from ents, so whatever
// remains and is still live has disappeared.
func (p *laterPlan) classifyEntities(k *tenantKeys, records []entityRecord, ents map[string]entState) (int64, error) {
	var seals int64
	seen := make(map[string]bool, len(records))
	for i := range records {
		e := &records[i]
		if !providerCodes.valid(e.provider) || !nodeTypeCodes.valid(e.nodeType) {
			return 0, fmt.Errorf("store: entity %d has provider %d and type %d, which are not codes", i, e.provider, e.nodeType)
		}
		tags, err := canonicalMap(e.tags)
		if err != nil {
			return 0, err
		}
		attrs, err := canonicalMap(e.attributes)
		if err != nil {
			return 0, err
		}
		hashAttrs, err := canonicalMap(stableAttributes(e.attributes))
		if err != nil {
			return 0, err
		}
		sid := string(k.stableID(e.nativeID))
		if seen[sid] {
			return 0, fmt.Errorf("store: entity %d repeats an identity already in this scan", i)
		}
		seen[sid] = true
		h := entityContentHash(k, e.provider, e.nodeType, e.criticality, e.nativeID, e.name, tags, hashAttrs)
		cur, ok := ents[sid]
		delete(ents, sid) // remaining current entities disappeared
		switch {
		case !ok:
			p.entAppeared = append(p.entAppeared, i)
			seals += 2 + optionalSeal(tags) + optionalSeal(attrs) // native_id + name always
		case cur.gone:
			p.nodeByPos[i] = cur.nodeID
			p.entReappeared = append(p.entReappeared, entChange{pos: i, nodeID: cur.nodeID})
			seals += 1 + optionalSeal(tags) + optionalSeal(attrs) // name re-sealed, native unchanged
		case bytes.Equal(cur.hash, h):
			p.nodeByPos[i] = cur.nodeID // unchanged: bulk last_seen bump only
		default:
			p.nodeByPos[i] = cur.nodeID
			p.entChanged = append(p.entChanged, entChange{pos: i, nodeID: cur.nodeID})
			seals += 1 + optionalSeal(tags) + optionalSeal(attrs)
		}
	}
	for _, st := range ents {
		if !st.gone {
			p.entGone = append(p.entGone, entGone{nodeID: st.nodeID, hash: st.hash})
		}
	}
	return seals, nil
}

// classifyEdges decides each observed edge. An edge touching a newly appeared
// entity cannot already exist, so it is appeared without a lookup.
func (p *laterPlan) classifyEdges(k *tenantKeys, records []edgeRecord, evidence []evidenceRecord, cur map[edgeKey]edgeState) (int64, error) {
	var seals int64
	for i := range records {
		e := &records[i]
		if !edgeKindCodes.valid(e.kind) || e.evidence < 0 || e.evidence >= len(evidence) {
			return 0, fmt.Errorf("store: edge %d has kind %d and evidence %d, which are not valid", i, e.kind, e.evidence)
		}
		if e.src < 0 || e.src >= len(p.nodeByPos) || e.dst < 0 || e.dst >= len(p.nodeByPos) {
			return 0, fmt.Errorf("store: edge %d references an entity position out of range", i)
		}
		cond, err := canonicalMap(e.conditions)
		if err != nil {
			return 0, err
		}
		srcNode, dstNode := p.nodeByPos[e.src], p.nodeByPos[e.dst]
		if srcNode == 0 || dstNode == 0 {
			p.edgeAppeared = append(p.edgeAppeared, i)
			seals += optionalSeal(cond)
			continue
		}
		key := edgeKey{src: srcNode, kind: e.kind, dst: dstNode}
		st, ok := cur[key]
		if ok {
			delete(cur, key) // remaining current edges disappeared
		}
		h := edgeContentHash(k, e.confidence, cond)
		switch {
		case !ok:
			p.edgeAppeared = append(p.edgeAppeared, i)
			seals += optionalSeal(cond)
		case bytes.Equal(st.hash, h): // unchanged
		default:
			p.edgeChanged = append(p.edgeChanged, edgeChange{pos: i, edgeID: st.edgeID})
			seals += optionalSeal(cond)
		}
	}
	for key, st := range cur {
		p.edgeGone = append(p.edgeGone, edgeGone{edgeID: st.edgeID, src: key.src, kind: key.kind, dst: key.dst, hash: st.hash})
	}
	return seals, nil
}

// optionalSeal is 1 when a canonical value will be sealed, 0 when it is empty
// (NULL, no encryption). It keeps the plan's seal count exactly equal to what
// the apply performs.
func optionalSeal(canonical []byte) int64 {
	if canonical == nil {
		return 0
	}
	return 1
}

func loadEntityState(ctx context.Context, tx *sql.Tx) (map[string]entState, error) {
	rows, err := tx.QueryContext(ctx, "SELECT stable_id, node_id, content_hash, gone_scan FROM entities")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := map[string]entState{}
	for rows.Next() {
		var sid, hash []byte
		var node int64
		var gone sql.NullInt64
		if err := rows.Scan(&sid, &node, &hash, &gone); err != nil {
			return nil, err
		}
		m[string(sid)] = entState{nodeID: node, hash: hash, gone: gone.Valid}
	}
	return m, rows.Err()
}

func loadEdgeState(ctx context.Context, tx *sql.Tx) (map[edgeKey]edgeState, error) {
	rows, err := tx.QueryContext(ctx, "SELECT src, kind, dst, edge_id, content_hash FROM edges")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := map[edgeKey]edgeState{}
	for rows.Next() {
		var key edgeKey
		var edgeID int64
		var hash []byte
		if err := rows.Scan(&key.src, &key.kind, &key.dst, &edgeID, &hash); err != nil {
			return nil, err
		}
		m[key] = edgeState{edgeID: edgeID, hash: hash}
	}
	return m, rows.Err()
}

// applyLaterScan writes the plan in one atomic transaction, drawing every
// encryption from the reservation. A returned error or a cancelled context
// rolls the whole scan back (ADR-0014 §3); the forfeited slots are the B-6
// safe over-count.
func (t *Tenant) applyLaterScan(ctx context.Context, s laterScan, p *laterPlan, res *reservation) (int64, error) {
	var scanID int64
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) error {
			// Non-cancellable to avoid the shared-connection rollback race; see
			// the comment on BeginTx in (*Tenant).Update (repo.go).
			tx, err := c.BeginTx(context.WithoutCancel(ctx), nil)
			if err != nil {
				return err
			}
			w := &loadWriter{ctx: ctx, tx: tx, k: k, res: res}
			scanID = w.applyPlan(s, p)
			w.pruneToRetention() // bound growth, atomically with this scan (ADR-0011 §1)
			// After the scan's writes and retention, an entity marked gone whose
			// last reference is now gone can be removed (ADR-0011 §1).
			phaseDo("gone_gc", func() { w.collectGoneEntities() })
			if err := errors.Join(w.err, w.close()); err != nil {
				return errors.Join(err, tx.Rollback())
			}
			if err := ctx.Err(); err != nil {
				return errors.Join(err, tx.Rollback())
			}
			return tx.Commit()
		})
	})
	return scanID, err
}

func (w *loadWriter) applyPlan(s laterScan, p *laterPlan) int64 {
	scanID := w.insertScan(s.toolVersion, s.manifest, s.started, s.completed)
	evidenceBase := w.insertEvidence(scanID, s.evidence)
	at := millis(s.completed)

	appearedBase := w.nextID("entities")
	for j, pos := range p.entAppeared {
		node := appearedBase + int64(j)
		p.nodeByPos[pos] = node
		w.appearEntity(scanID, node, at, &s.entities[pos])
	}
	appeared, _ := changeCodes.code("appeared")
	changed, _ := changeCodes.code("changed")
	disappeared, _ := changeCodes.code("disappeared")
	for _, ch := range p.entReappeared {
		w.changeEntity(scanID, ch.nodeID, &s.entities[ch.pos], appeared, true)
	}
	for _, ch := range p.entChanged {
		w.changeEntity(scanID, ch.nodeID, &s.entities[ch.pos], changed, false)
	}
	for _, g := range p.entGone {
		w.goneEntity(scanID, g, disappeared)
	}
	phaseDo("entity_bump", func() {
		w.exec(w.prep("UPDATE entities SET last_seen_scan = ?, last_seen_at = ? WHERE gone_scan IS NULL"), scanID, at)
	})

	appearedEdgeBase := w.nextID("edges")
	// Edges carry no bulk last_seen bump. A disappeared edge is deleted, so a
	// present edge is current by definition and its history is in edge_snapshots;
	// last_seen_scan is set when the edge appears or its content changes, and an
	// unchanged edge keeps the scan that last wrote it. This is unlike entities,
	// which are soft-marked gone and so must have last_seen bumped every scan, so
	// a gone entity records the last scan it was present. Not bumping unchanged
	// edges is the B-4 optimization: it avoids rewriting every edge row each scan.
	phaseDo("edge_churn", func() {
		for _, g := range p.edgeGone {
			w.goneEdge(scanID, g, disappeared)
		}
		for j, pos := range p.edgeAppeared {
			w.appearEdge(scanID, appearedEdgeBase+int64(j), &s.edges[pos], p.nodeByPos, evidenceBase, s.evidence)
		}
		for _, ch := range p.edgeChanged {
			w.changeEdge(scanID, ch.edgeID, &s.edges[ch.pos], p.nodeByPos, evidenceBase, s.evidence, changed)
		}
	})

	// Permissions, exposures, and classifications, now that every entity has a
	// node ID. These carry no history and are deleted on disappearance.
	w.scanID, w.entities, w.nodeByPos = scanID, s.entities, p.nodeByPos
	phaseDo("model_tables", func() { w.applyModelTables(s, p) })
	// Scopes are per-scan coverage, not diffed: inserted for every scan, like
	// evidence.
	w.insertScopes(scanID, s.scopes)
	return scanID
}

// prep returns a prepared statement for query, reusing one across rows so a
// churn of thousands does not prepare thousands of times.
func (w *loadWriter) prep(query string) *sql.Stmt {
	if st := w.cache[query]; st != nil {
		return st
	}
	st := w.prepare(query)
	if st != nil {
		if w.cache == nil {
			w.cache = map[string]*sql.Stmt{}
		}
		w.cache[query] = st
	}
	return st
}

func (w *loadWriter) appearEntity(scanID, node, at int64, e *entityRecord) {
	tags, err := canonicalMap(e.tags)
	w.fail(err)
	attrs, err := canonicalMap(e.attributes)
	w.fail(err)
	hashAttrs, err := canonicalMap(stableAttributes(e.attributes))
	w.fail(err)
	content := entityContentHash(w.k, e.provider, e.nodeType, e.criticality, e.nativeID, e.name, tags, hashAttrs)
	w.exec(w.prep(`INSERT INTO entities (node_id, tenant_id, stable_id, provider, type, native_id_sealed, name_sealed,
		tags_sealed, attributes_sealed, criticality, content_hash, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		node, w.k.id, w.k.stableID(e.nativeID), e.provider, e.nodeType,
		w.seal(FieldEntityNativeID(), node, []byte(e.nativeID)), w.seal(FieldEntityName(), node, []byte(e.name)),
		w.sealOptional(FieldEntityTags(), node, tags), w.sealOptional(FieldEntityAttributes(), node, attrs),
		e.criticality, content, scanID, scanID, at, at)
	appeared, _ := changeCodes.code("appeared")
	w.entitySnapshot(scanID, node, appeared, content)
}

// changeEntity rewrites a changed or a reappeared entity's mutable content and
// records the change. It never re-seals native_id, the immutable identity.
// last_seen is left to the bulk bump. reappear clears gone_scan.
func (w *loadWriter) changeEntity(scanID, node int64, e *entityRecord, change int64, reappear bool) {
	tags, err := canonicalMap(e.tags)
	w.fail(err)
	attrs, err := canonicalMap(e.attributes)
	w.fail(err)
	hashAttrs, err := canonicalMap(stableAttributes(e.attributes))
	w.fail(err)
	content := entityContentHash(w.k, e.provider, e.nodeType, e.criticality, e.nativeID, e.name, tags, hashAttrs)
	query := `UPDATE entities SET provider = ?, type = ?, name_sealed = ?, tags_sealed = ?, attributes_sealed = ?,
		criticality = ?, content_hash = ? WHERE node_id = ?`
	if reappear {
		query = `UPDATE entities SET provider = ?, type = ?, name_sealed = ?, tags_sealed = ?, attributes_sealed = ?,
			criticality = ?, content_hash = ?, gone_scan = NULL WHERE node_id = ?`
	}
	w.exec(w.prep(query), e.provider, e.nodeType,
		w.seal(FieldEntityName(), node, []byte(e.name)),
		w.sealOptional(FieldEntityTags(), node, tags), w.sealOptional(FieldEntityAttributes(), node, attrs),
		e.criticality, content, node)
	w.entitySnapshot(scanID, node, change, content)
}

func (w *loadWriter) goneEntity(scanID int64, g entGone, disappeared int64) {
	w.exec(w.prep("UPDATE entities SET gone_scan = ? WHERE node_id = ? AND gone_scan IS NULL"), scanID, g.nodeID)
	w.entitySnapshot(scanID, g.nodeID, disappeared, g.hash)
}

func (w *loadWriter) entitySnapshot(scanID, node, change int64, contentHash []byte) {
	var noContent []byte
	w.exec(w.prep(`INSERT INTO entity_snapshots (tenant_id, scan_id, node_id, change, schema_version, content_sealed, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		w.k.id, scanID, node, change, int64(model.SchemaVersion), noContent, contentHash)
}

func (w *loadWriter) appearEdge(scanID, edgeID int64, e *edgeRecord, nodeByPos []int64, evidenceBase int64, evidence []evidenceRecord) {
	cond, err := canonicalMap(e.conditions)
	w.fail(err)
	src, dst := nodeByPos[e.src], nodeByPos[e.dst]
	content := edgeContentHash(w.k, e.confidence, cond)
	w.exec(w.prep(`INSERT INTO edges (edge_id, tenant_id, src, kind, dst, conditions_sealed, confidence, evidence_id, observed_at, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		edgeID, w.k.id, src, e.kind, dst, w.sealOptional(FieldEdgeConditions(), edgeID, cond), e.confidence,
		evidenceBase+int64(e.evidence), millis(evidence[e.evidence].observed), content, scanID, scanID)
	appeared, _ := changeCodes.code("appeared")
	w.edgeSnapshot(scanID, edgeID, appeared, src, e.kind, dst, content)
}

func (w *loadWriter) changeEdge(scanID, edgeID int64, e *edgeRecord, nodeByPos []int64, evidenceBase int64, evidence []evidenceRecord, change int64) {
	cond, err := canonicalMap(e.conditions)
	w.fail(err)
	src, dst := nodeByPos[e.src], nodeByPos[e.dst]
	content := edgeContentHash(w.k, e.confidence, cond)
	w.exec(w.prep(`UPDATE edges SET conditions_sealed = ?, confidence = ?, evidence_id = ?, observed_at = ?, content_hash = ?, last_seen_scan = ? WHERE edge_id = ?`),
		w.sealOptional(FieldEdgeConditions(), edgeID, cond), e.confidence,
		evidenceBase+int64(e.evidence), millis(evidence[e.evidence].observed), content, scanID, edgeID)
	w.edgeSnapshot(scanID, edgeID, change, src, e.kind, dst, content)
}

func (w *loadWriter) goneEdge(scanID int64, g edgeGone, disappeared int64) {
	w.edgeSnapshot(scanID, g.edgeID, disappeared, g.src, g.kind, g.dst, g.hash)
	w.exec(w.prep("DELETE FROM edges WHERE edge_id = ?"), g.edgeID)
}

func (w *loadWriter) edgeSnapshot(scanID, edgeID, change, src, kind, dst int64, contentHash []byte) {
	var noConditions []byte
	w.exec(w.prep(`INSERT INTO edge_snapshots (tenant_id, scan_id, edge_id, change, src, kind, dst, conditions_sealed, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		w.k.id, scanID, edgeID, change, src, kind, dst, noConditions, contentHash)
}
