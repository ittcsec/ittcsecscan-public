package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"time"
)

// The initial load of a new tenant's first scan. It writes exactly what
// ingest will write for a first scan: every object appears, and its first
// and last scans are this one. A tenant's first scan writes no change
// records, because every object in it appeared and first_seen_scan already
// says so; later scans' change records keep the file close to its
// current-state size plus actual churn (ADR-0011 §1). Ingest of later scans,
// which compares them with the current state, comes with the repository
// interfaces. Today this path serves the fixtures and the scale benchmark.

// firstScan is a new tenant's first scan.
type firstScan struct {
	toolVersion        string
	manifest           []byte
	started, completed time.Time
	evidence           []evidenceRecord
	entities           []entityRecord
	edges              iter.Seq[edgeRecord] // nil for none
	labels             []labelRecord
	permissions        []permissionRecord
	exposures          []exposureRecord
	scopes             []scopeRecord
}

// scopeRecord is one enumeration's coverage: what a collector tried to read and
// how completely it managed. provider, completeness, and reason are codes;
// account and region are sealed; reason is 0 when completeness is complete or
// partial (a scopeReasonCodes value otherwise).
type scopeRecord struct {
	provider     int64
	account      string
	region       string // "" for none (a global scope carries its region as "global")
	requested    int
	observed     int
	completeness int64
	reason       int64
}

// evidenceRecord is one observation. Its value is already redacted.
type evidenceRecord struct {
	collector, api string
	observed       time.Time
	value          []byte
}

type entityRecord struct {
	nativeID    string
	name        string
	provider    int64 // providerCodes
	nodeType    int64 // nodeTypeCodes
	criticality int64
	tags        map[string]string
	attributes  map[string]string
}

// edgeRecord links two entities, by their positions in firstScan.entities.
// evidence is a position in firstScan.evidence; the edge was observed when
// its evidence was.
type edgeRecord struct {
	src, dst   int
	kind       int64 // edgeKindCodes
	confidence int64
	evidence   int
	conditions map[string]string
}

type labelRecord struct {
	entity        int
	label, method string
	confidence    int64
	sample        map[string]string // approved_sample, optional
}

// permissionRecord is one effective permission: principal may take action on
// resource with effect, optionally under conditions and inherited from another
// entity. principal, resource, and inheritedFrom are positions in the scan's
// entities; inheritedFrom is negative for none.
type permissionRecord struct {
	principal, resource int
	action              string
	effect              int64 // permission effect code, positive
	condition           map[string]string
	inheritedFrom       int
}

// exposureRecord is one effective-reachability fact for an entity. node is a
// position in the scan's entities. protocol is an IANA number, or negative for
// any; portFrom and portTo are a range, or both negative for any port.
// authRequired and effective are tri-states (0 no, 1 yes, 2 unknown).
type exposureRecord struct {
	node                    int
	sourceZone              int64
	protocol                int64
	portFrom, portTo        int64
	authRequired, effective int64
	trace                   map[string]string
}

// bulkLoadCacheKiB is the page cache of a first-scan load, in KiB: 256 MiB,
// during the load only (owner decision, 2026-09-13). With SQLite's default of
// about 2 MB, the 500,000-entity load spent most of its time in operating
// system reads and writes; 1 GiB gained nothing over 256 MiB.
const bulkLoadCacheKiB = 256 * 1024

// loadFirstScan writes a new tenant's first scan in one transaction, with the
// bulk-load page cache, then refreshes statistics (ADR-0011 §4). It refuses a
// tenant that already has a scan, writes nothing if any record is invalid,
// and puts the page cache back as it was, whatever happens.
//
// Every encryption it performs is counted (B-6): it reserves exactly the seals
// the load will draw, committed before the load, so a crash forfeits the slots
// (a safe over-count) rather than seal uncounted. The first scan is the largest
// seal operation in the system, so this is where most of a data key's budget is
// spent. s.edges is iterated twice, once to count and once to load, so it must
// be restartable (every caller's is).
func (t *Tenant) loadFirstScan(ctx context.Context, s firstScan) (int64, error) {
	seals, err := firstScanSealCount(s)
	if err != nil {
		return 0, err
	}
	res, err := t.reserveSeals(ctx, seals)
	if err != nil {
		return 0, err
	}
	var scanID int64
	err = t.withConn(ctx, func(c *sql.Conn) (err error) {
		restore, err := setCacheSize(ctx, c, -bulkLoadCacheKiB)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, restore()) }()
		return t.withKeys(func(k *tenantKeys) error {
			tx, err := c.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if scanID, err = writeFirstScan(ctx, tx, k, res, s); err != nil {
				return errors.Join(err, tx.Rollback())
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			_, err = c.ExecContext(ctx, "ANALYZE")
			return err
		})
	})
	return scanID, err
}

// firstScanSealCount is exactly the number of encryptions writeFirstScan will
// perform: the manifest, each evidence value present, each entity's native ID
// and name plus any tags and attributes, each edge's conditions, and each
// label's name and method. It must track writeFirstScan's seals precisely, so
// the reservation is neither short (which would fail the load) nor wasteful.
func firstScanSealCount(s firstScan) (int64, error) {
	seals := int64(1) // the scan manifest
	for i := range s.evidence {
		if s.evidence[i].value != nil {
			seals++
		}
	}
	for i := range s.entities {
		tags, err := canonicalMap(s.entities[i].tags)
		if err != nil {
			return 0, err
		}
		attrs, err := canonicalMap(s.entities[i].attributes)
		if err != nil {
			return 0, err
		}
		seals += 2 + optionalSeal(tags) + optionalSeal(attrs) // native_id + name always
	}
	if s.edges != nil {
		for e := range s.edges {
			cond, err := canonicalMap(e.conditions)
			if err != nil {
				return 0, err
			}
			seals += optionalSeal(cond)
		}
	}
	for i := range s.labels {
		sample, err := canonicalMap(s.labels[i].sample)
		if err != nil {
			return 0, err
		}
		seals += 2 + optionalSeal(sample) // label + method always, sample if present
	}
	for i := range s.permissions {
		cond, err := canonicalMap(s.permissions[i].condition)
		if err != nil {
			return 0, err
		}
		seals += optionalSeal(cond)
	}
	for i := range s.exposures {
		trace, err := canonicalMap(s.exposures[i].trace)
		if err != nil {
			return 0, err
		}
		seals += optionalSeal(trace)
	}
	for i := range s.scopes {
		seals++ // scope account, always sealed
		if s.scopes[i].region != "" {
			seals++ // scope region, sealed when present
		}
	}
	return seals, nil
}

func writeFirstScan(ctx context.Context, tx *sql.Tx, k *tenantKeys, res *reservation, s firstScan) (int64, error) {
	var scans int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM scans").Scan(&scans); err != nil {
		return 0, err
	}
	if scans != 0 {
		return 0, errors.New("store: the initial load is only for a tenant with no scans")
	}
	if err := requireCacheSize(ctx, tx, -bulkLoadCacheKiB); err != nil {
		return 0, fmt.Errorf("store: the initial load must run with the bulk-load page cache: %w", err)
	}
	w := &loadWriter{ctx: ctx, tx: tx, k: k, res: res}
	scanID := w.insertScan(s.toolVersion, s.manifest, s.started, s.completed)
	evidence := w.insertEvidence(scanID, s.evidence)
	indexes := w.dropBulkIndexes()
	nodes := w.insertEntities(scanID, s.completed, s.entities)
	w.insertEdges(scanID, s.edges, nodes, evidence, s.evidence)
	w.insertLabels(scanID, s.labels, nodes, s.entities)
	w.insertPermissions(scanID, s.permissions, nodes, s.entities)
	w.insertExposures(scanID, s.exposures, nodes, s.entities)
	w.insertScopes(scanID, s.scopes)
	w.createIndexes(indexes)
	return scanID, errors.Join(w.err, w.close())
}

// sqlBulkIndexes lists the secondary indexes of the tables a first scan
// fills in bulk. They are built after the rows, not row by row (ADR-0011 §4,
// decision 4). Rebuilding a unique index still refuses a duplicate, and a
// failed load rolls the drop back with everything else.
const sqlBulkIndexes = `SELECT name, sql FROM sqlite_schema
	WHERE type = 'index' AND sql IS NOT NULL AND tbl_name IN ('entities', 'edges', 'classifications') ORDER BY name`

// bulkIndex is one secondary index dropped for the load: its name, and its
// CREATE statement exactly as sqlite_schema stored it.
type bulkIndex struct{ name, def string }

// dropBulkIndexes drops the bulk tables' secondary indexes and returns their
// definitions, exactly as the migrations wrote them.
func (w *loadWriter) dropBulkIndexes() []bulkIndex {
	if w.err != nil {
		return nil
	}
	rows, err := w.tx.QueryContext(w.ctx, sqlBulkIndexes)
	if err != nil {
		w.fail(err)
		return nil
	}
	var indexes []bulkIndex
	for rows.Next() {
		var ix bulkIndex
		if err := rows.Scan(&ix.name, &ix.def); err != nil {
			w.fail(err)
			break
		}
		indexes = append(indexes, ix)
	}
	w.fail(errors.Join(rows.Err(), rows.Close()))
	for _, ix := range indexes {
		if w.err != nil {
			break
		}
		// A doubled quote keeps a hostile index name inside the identifier.
		_, err := w.tx.ExecContext(w.ctx, `DROP INDEX "`+strings.ReplaceAll(ix.name, `"`, `""`)+`"`)
		w.fail(err)
	}
	return indexes
}

// createIndexes rebuilds each index from its stored definition, then reads the
// definition back and requires it to be byte-for-byte what was stored. The
// driver runs every statement in a string, so a tampered file could hide extra
// statements after a CREATE INDEX; running the stored text and then comparing
// what SQLite recorded for the index catches that (the recorded text is only
// the CREATE INDEX itself), and the whole load is one transaction, so a
// mismatch rolls back every statement the tampered text ran (threat T-29).
func (w *loadWriter) createIndexes(indexes []bulkIndex) {
	for _, ix := range indexes {
		if w.err != nil {
			return
		}
		if _, err := w.tx.ExecContext(w.ctx, ix.def); err != nil {
			w.fail(err)
			return
		}
		var got string
		if err := w.tx.QueryRowContext(w.ctx, "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?", ix.name).Scan(&got); err != nil {
			w.fail(err)
			return
		}
		if got != ix.def {
			w.fail(fmt.Errorf("%w: rebuilding index %q recorded %q, not the stored definition %q", ErrForeignFile, ix.name, got, ix.def))
			return
		}
	}
}

// setCacheSize sets the connection's page cache (PRAGMA cache_size; a
// negative size is in KiB), checks that it took effect, and returns a
// function that restores the previous size, even after ctx is cancelled.
func setCacheSize(ctx context.Context, c *sql.Conn, size int64) (func() error, error) {
	var before int64
	if err := c.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&before); err != nil {
		return nil, err
	}
	set := func(ctx context.Context, n int64) error {
		if _, err := c.ExecContext(ctx, "PRAGMA cache_size = "+strconv.FormatInt(n, 10)); err != nil {
			return err
		}
		return requireCacheSize(ctx, c, n)
	}
	if err := set(ctx, size); err != nil {
		return nil, errors.Join(err, set(context.WithoutCancel(ctx), before))
	}
	return func() error { return set(context.WithoutCancel(ctx), before) }, nil
}

// requireCacheSize fails unless the connection's page cache is size.
func requireCacheSize(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, size int64) error {
	var got int64
	if err := q.QueryRowContext(ctx, "PRAGMA cache_size").Scan(&got); err != nil {
		return err
	}
	if got != size {
		return fmt.Errorf("store: the page cache is %d, want %d", got, size)
	}
	return nil
}

// loadWriter writes one load, keeping the first error and skipping every
// write after it. When res is set, every seal draws a slot from it first, so
// the encryptions the load performs are counted and bounded (B-6); a first
// scan today leaves res nil and is not yet counted.
type loadWriter struct {
	ctx context.Context
	tx  *sql.Tx
	k   *tenantKeys
	res *reservation
	// scanID, entities, and nodeByPos are the later-scan apply context: the
	// scan being applied, its entity records (for identity stable IDs), and the
	// position-to-node-ID resolution. They are unset for a first-scan load.
	scanID    int64
	entities  []entityRecord
	nodeByPos []int64
	stmts     []*sql.Stmt
	cache     map[string]*sql.Stmt // prepared statements reused across rows (prep)
	err       error
}

// entitySID is the stable ID of the entity at position pos in the later scan.
func (w *loadWriter) entitySID(pos int) []byte { return w.k.stableID(w.entities[pos].nativeID) }

func (w *loadWriter) fail(err error) {
	if w.err == nil && err != nil {
		w.err = err
	}
}

func (w *loadWriter) prepare(query string) *sql.Stmt {
	if w.err != nil {
		return nil
	}
	st, err := w.tx.PrepareContext(w.ctx, query)
	if err != nil {
		w.fail(err)
		return nil
	}
	w.stmts = append(w.stmts, st)
	return st
}

func (w *loadWriter) exec(st *sql.Stmt, args ...any) {
	if w.err != nil {
		return
	}
	_, err := st.ExecContext(w.ctx, args...)
	w.fail(err)
}

func (w *loadWriter) close() error {
	var errs []error
	for _, st := range w.stmts {
		errs = append(errs, st.Close())
	}
	return errors.Join(errs...)
}

// nextID returns the first key AUTOINCREMENT would give table's next row.
// Keys are assigned explicitly, so values can be sealed with their row's key
// before the row is written; SQLite then advances the sequence past them.
func (w *loadWriter) nextID(table string) int64 {
	if w.err != nil {
		return 0
	}
	var seq int64
	w.fail(w.tx.QueryRowContext(w.ctx, "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = ?), 0)", table).Scan(&seq))
	return seq + 1
}

func (w *loadWriter) seal(f Field, row int64, plaintext []byte) []byte {
	if w.err != nil {
		return nil
	}
	if w.res != nil {
		if err := w.res.take(); err != nil {
			w.fail(err)
			return nil
		}
	}
	b, err := w.k.seal(f, row, plaintext)
	w.fail(err)
	return b
}

// sealOptional seals plaintext, or returns nil (a NULL column) when there is
// nothing to seal. Canonical bytes for an empty map are nil, so an absent tag
// set, attribute set, or condition set is stored as NULL and performs no
// encryption.
func (w *loadWriter) sealOptional(f Field, row int64, plaintext []byte) []byte {
	if plaintext == nil {
		return nil
	}
	return w.seal(f, row, plaintext)
}

func millis(t time.Time) int64 { return t.UTC().UnixMilli() }

func (w *loadWriter) insertScan(toolVersion string, manifest []byte, started, completed time.Time) int64 {
	id := w.nextID("scans")
	status, _ := scanStatusCodes.code("completed")
	st := w.prepare(`INSERT INTO scans (scan_id, tenant_id, started_at, completed_at, tool_version, status, manifest_sealed, manifest_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	w.exec(st, id, w.k.id, millis(started), millis(completed), toolVersion, status,
		w.seal(FieldScanManifest(), id, manifest), w.k.hash(hashScanManifest, string(manifest)))
	return id
}

func (w *loadWriter) insertEvidence(scanID int64, records []evidenceRecord) int64 {
	base := w.nextID("evidence")
	fresh, _ := freshnessCodes.code("fresh")
	complete, _ := completenessCodes.code("complete")
	st := w.prepare(`INSERT INTO evidence (evidence_id, tenant_id, scan_id, collector, api, observed_at, redacted_value_sealed, value_hash, freshness, completeness)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, e := range records {
		id := base + int64(i)
		w.exec(st, id, w.k.id, scanID, e.collector, e.api, millis(e.observed),
			w.sealOptional(FieldEvidenceValue(), id, e.value), w.k.hash(hashEvidenceValue, string(e.value)), fresh, complete)
	}
	return base
}

// insertScopes writes one scan's coverage records. account is sealed always,
// region when present; reason is NULL when it is not a scope-reason code.
func (w *loadWriter) insertScopes(scanID int64, records []scopeRecord) {
	if len(records) == 0 {
		return
	}
	base := w.nextID("scopes")
	st := w.prepare(`INSERT INTO scopes (scope_id, tenant_id, scan_id, provider, account_sealed, region_sealed, requested, observed, completeness, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, r := range records {
		id := base + int64(i)
		var region []byte
		if r.region != "" {
			region = []byte(r.region)
		}
		var reason any
		if r.reason > 0 {
			reason = r.reason
		}
		w.exec(st, id, w.k.id, scanID, r.provider,
			w.seal(FieldScopeAccount(), id, []byte(r.account)),
			w.sealOptional(FieldScopeRegion(), id, region),
			r.requested, r.observed, r.completeness, reason)
	}
}

// insertEntities writes every entity and returns the first node ID; entity
// i is node first+i.
func (w *loadWriter) insertEntities(scanID int64, seen time.Time, records []entityRecord) int64 {
	base := w.nextID("entities")
	st := w.prepare(`INSERT INTO entities (node_id, tenant_id, stable_id, provider, type, native_id_sealed, name_sealed,
		tags_sealed, attributes_sealed, criticality, content_hash, first_seen_scan, last_seen_scan, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	at := millis(seen)
	for i, e := range records {
		if !providerCodes.valid(e.provider) || !nodeTypeCodes.valid(e.nodeType) {
			w.fail(fmt.Errorf("store: entity %d has provider %d and type %d, which are not codes", i, e.provider, e.nodeType))
		}
		node := base + int64(i)
		tags, err := canonicalMap(e.tags)
		w.fail(err)
		attributes, err := canonicalMap(e.attributes)
		w.fail(err)
		hashAttrs, err := canonicalMap(stableAttributes(e.attributes))
		w.fail(err)
		content := entityContentHash(w.k, e.provider, e.nodeType, e.criticality, e.nativeID, e.name, tags, hashAttrs)
		w.exec(st, node, w.k.id, w.k.stableID(e.nativeID), e.provider, e.nodeType,
			w.seal(FieldEntityNativeID(), node, []byte(e.nativeID)), w.seal(FieldEntityName(), node, []byte(e.name)),
			w.sealOptional(FieldEntityTags(), node, tags), w.sealOptional(FieldEntityAttributes(), node, attributes),
			e.criticality, content, scanID, scanID, at, at)
	}
	return base
}

func (w *loadWriter) insertEdges(scanID int64, edges iter.Seq[edgeRecord], nodes, evidenceBase int64, evidence []evidenceRecord) {
	if edges == nil {
		return
	}
	base := w.nextID("edges")
	st := w.prepare(`INSERT INTO edges (edge_id, tenant_id, src, kind, dst, conditions_sealed, confidence, evidence_id, observed_at, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	i := int64(0)
	for e := range edges {
		if w.err != nil {
			return
		}
		if !edgeKindCodes.valid(e.kind) || e.evidence < 0 || e.evidence >= len(evidence) {
			w.fail(fmt.Errorf("store: edge %d has kind %d and evidence %d, which are not valid", i, e.kind, e.evidence))
			return
		}
		edgeID := base + i
		conditions, err := canonicalMap(e.conditions)
		w.fail(err)
		// The content hash covers the confidence and the conditions (B-1): a
		// change in either between scans must be detectable, or no change
		// record is written (ADR-0011 §1).
		content := edgeContentHash(w.k, e.confidence, conditions)
		w.exec(st, edgeID, w.k.id, nodes+int64(e.src), e.kind, nodes+int64(e.dst),
			w.sealOptional(FieldEdgeConditions(), edgeID, conditions), e.confidence,
			evidenceBase+int64(e.evidence), millis(evidence[e.evidence].observed), content, scanID, scanID)
		i++
	}
}

func (w *loadWriter) insertLabels(scanID int64, labels []labelRecord, nodes int64, entities []entityRecord) {
	if len(labels) == 0 {
		return
	}
	base := w.nextID("classifications")
	st := w.prepare(`INSERT INTO classifications (classification_id, tenant_id, classification_hash, node_id, label_sealed, method_sealed,
		confidence, approved_sample_sealed, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, l := range labels {
		if !validEntityPos(l.entity, entities) {
			w.fail(fmt.Errorf("store: label %d names entity %d, which does not exist", i, l.entity))
			return
		}
		id := base + int64(i)
		sid := w.k.stableID(entities[l.entity].nativeID)
		sample, err := canonicalMap(l.sample)
		w.fail(err)
		identity := classificationIdentity(w.k, sid, l.label, l.method)
		content := classificationContentHash(w.k, l.confidence, sample)
		w.exec(st, id, w.k.id, identity, nodes+int64(l.entity),
			w.seal(FieldClassificationLabel(), id, []byte(l.label)), w.seal(FieldClassificationMethod(), id, []byte(l.method)),
			l.confidence, w.sealOptional(FieldClassificationSample(), id, sample), content, scanID, scanID)
	}
}

func (w *loadWriter) insertPermissions(scanID int64, perms []permissionRecord, nodes int64, entities []entityRecord) {
	if len(perms) == 0 {
		return
	}
	base := w.nextID("permissions")
	st := w.prepare(`INSERT INTO permissions (permission_id, tenant_id, permission_hash, principal, resource, action, effect,
		condition_sealed, inherited_from, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i := range perms {
		p := &perms[i]
		if !validEntityPos(p.principal, entities) || !validEntityPos(p.resource, entities) ||
			(p.inheritedFrom >= 0 && !validEntityPos(p.inheritedFrom, entities)) {
			w.fail(fmt.Errorf("store: permission %d references an entity out of range", i))
			return
		}
		if p.effect <= 0 {
			w.fail(fmt.Errorf("store: permission %d has effect %d, which is not a code", i, p.effect))
			return
		}
		id := base + int64(i)
		cond, err := canonicalMap(p.condition)
		w.fail(err)
		principalSID := w.k.stableID(entities[p.principal].nativeID)
		resourceSID := w.k.stableID(entities[p.resource].nativeID)
		var inheritedNode any
		var inheritedSID []byte
		if p.inheritedFrom >= 0 {
			inheritedNode = nodes + int64(p.inheritedFrom)
			inheritedSID = w.k.stableID(entities[p.inheritedFrom].nativeID)
		}
		identity := permissionIdentity(w.k, principalSID, resourceSID, p.action)
		content := permissionContentHash(w.k, p.effect, cond, inheritedSID)
		w.exec(st, id, w.k.id, identity, nodes+int64(p.principal), nodes+int64(p.resource), p.action, p.effect,
			w.sealOptional(FieldPermissionCondition(), id, cond), inheritedNode, content, scanID, scanID)
	}
}

func (w *loadWriter) insertExposures(scanID int64, exps []exposureRecord, nodes int64, entities []entityRecord) {
	if len(exps) == 0 {
		return
	}
	base := w.nextID("exposures")
	st := w.prepare(`INSERT INTO exposures (exposure_id, tenant_id, exposure_hash, node_id, source_zone, protocol, port_from, port_to,
		auth_required, effective, trace_sealed, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i := range exps {
		e := &exps[i]
		if !validEntityPos(e.node, entities) {
			w.fail(fmt.Errorf("store: exposure %d names entity %d, which does not exist", i, e.node))
			return
		}
		if e.sourceZone <= 0 {
			w.fail(fmt.Errorf("store: exposure %d has source zone %d, which is not a code", i, e.sourceZone))
			return
		}
		id := base + int64(i)
		trace, err := canonicalMap(e.trace)
		w.fail(err)
		sid := w.k.stableID(entities[e.node].nativeID)
		identity := exposureIdentity(w.k, sid, e.sourceZone, e.protocol, e.portFrom, e.portTo)
		content := exposureContentHash(w.k, e.authRequired, e.effective, trace)
		w.exec(st, id, w.k.id, identity, nodes+int64(e.node), e.sourceZone,
			nullIfNegative(e.protocol), nullIfNegative(e.portFrom), nullIfNegative(e.portTo),
			e.authRequired, e.effective,
			w.sealOptional(FieldExposureTrace(), id, trace), content, scanID, scanID)
	}
}

// validEntityPos reports whether pos indexes the scan's entities.
func validEntityPos(pos int, entities []entityRecord) bool {
	return pos >= 0 && pos < len(entities)
}

// nullIfNegative maps a negative code to a NULL column value (any protocol, or
// any port), and a non-negative one to itself.
func nullIfNegative(n int64) any {
	if n < 0 {
		return nil
	}
	return n
}
