package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
)

// loadRowState loads a current-state table keyed by its identity hash column
// (permissions, exposures, classifications) into a map from the identity hash to
// the row's ID and content hash, for the later-scan diff.
func loadRowState(ctx context.Context, tx *sql.Tx, table, idCol, pkCol string) (map[string]rowState, error) {
	//nolint:gosec // G202: table and column names are compile-time constants passed by this file's callers, never user input
	rows, err := tx.QueryContext(ctx, "SELECT "+idCol+", "+pkCol+", content_hash FROM "+table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	m := map[string]rowState{}
	for rows.Next() {
		var identity, hash []byte
		var id int64
		if err := rows.Scan(&identity, &id, &hash); err != nil {
			return nil, err
		}
		m[string(identity)] = rowState{id: id, hash: hash}
	}
	return m, rows.Err()
}

// classifyByIdentity is the diff for a current-state table keyed by an identity
// hash. For each record it takes the identity, the content hash, and the seals
// an appeared or a changed apply would perform (they differ only for
// classifications). It consumes cur: whatever identity remains has disappeared.
// These tables keep no history and are deleted on disappearance, so gone is just
// the row IDs to delete.
func classifyByIdentity(n int, cur map[string]rowState,
	compute func(i int) (identity, content []byte, sealsAppeared, sealsChanged int64, err error),
) (appeared []int, changed []rowChange, gone []int64, seals int64, err error) {
	seen := make(map[string]bool, n)
	for i := range n {
		identity, content, sa, sc, err := compute(i)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		key := string(identity)
		if seen[key] {
			return nil, nil, nil, 0, fmt.Errorf("store: record %d repeats an identity already in this scan", i)
		}
		seen[key] = true
		st, ok := cur[key]
		if ok {
			delete(cur, key)
		}
		switch {
		case !ok:
			appeared = append(appeared, i)
			seals += sa
		case bytes.Equal(st.hash, content): // unchanged: no work, no seal
		default:
			changed = append(changed, rowChange{pos: i, id: st.id})
			seals += sc
		}
	}
	for _, st := range cur {
		gone = append(gone, st.id)
	}
	return appeared, changed, gone, seals, nil
}

func (p *laterPlan) classifyPermissions(k *tenantKeys, records []permissionRecord, entities []entityRecord, cur map[string]rowState) (int64, error) {
	appeared, changed, gone, seals, err := classifyByIdentity(len(records), cur, func(i int) ([]byte, []byte, int64, int64, error) {
		e := &records[i]
		if !validEntityPos(e.principal, entities) || !validEntityPos(e.resource, entities) ||
			(e.inheritedFrom >= 0 && !validEntityPos(e.inheritedFrom, entities)) {
			return nil, nil, 0, 0, fmt.Errorf("store: permission %d references an entity position out of range", i)
		}
		if e.effect <= 0 {
			return nil, nil, 0, 0, fmt.Errorf("store: permission %d has effect %d, which is not a code", i, e.effect)
		}
		cond, err := canonicalMap(e.condition)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		var inheritedSID []byte
		if e.inheritedFrom >= 0 {
			inheritedSID = k.stableID(entities[e.inheritedFrom].nativeID)
		}
		identity := permissionIdentity(k, k.stableID(entities[e.principal].nativeID), k.stableID(entities[e.resource].nativeID), e.action)
		content := permissionContentHash(k, e.effect, cond, inheritedSID)
		s := optionalSeal(cond) // condition is the only sealed field, re-sealed on appear and change
		return identity, content, s, s, nil
	})
	if err != nil {
		return 0, err
	}
	p.permAppeared, p.permChanged, p.permGone = appeared, changed, gone
	return seals, nil
}

func (p *laterPlan) classifyExposures(k *tenantKeys, records []exposureRecord, entities []entityRecord, cur map[string]rowState) (int64, error) {
	appeared, changed, gone, seals, err := classifyByIdentity(len(records), cur, func(i int) ([]byte, []byte, int64, int64, error) {
		e := &records[i]
		if !validEntityPos(e.node, entities) {
			return nil, nil, 0, 0, fmt.Errorf("store: exposure %d references an entity position out of range", i)
		}
		if e.sourceZone <= 0 {
			return nil, nil, 0, 0, fmt.Errorf("store: exposure %d has source zone %d, which is not a code", i, e.sourceZone)
		}
		trace, err := canonicalMap(e.trace)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		identity := exposureIdentity(k, k.stableID(entities[e.node].nativeID), e.sourceZone, e.protocol, e.portFrom, e.portTo)
		content := exposureContentHash(k, e.authRequired, e.effective, trace)
		s := optionalSeal(trace)
		return identity, content, s, s, nil
	})
	if err != nil {
		return 0, err
	}
	p.exposureAppeared, p.exposureChanged, p.exposureGone = appeared, changed, gone
	return seals, nil
}

func (p *laterPlan) classifyClassifications(k *tenantKeys, records []labelRecord, entities []entityRecord, cur map[string]rowState) (int64, error) {
	appeared, changed, gone, seals, err := classifyByIdentity(len(records), cur, func(i int) ([]byte, []byte, int64, int64, error) {
		l := &records[i]
		if !validEntityPos(l.entity, entities) {
			return nil, nil, 0, 0, fmt.Errorf("store: classification %d references an entity position out of range", i)
		}
		sample, err := canonicalMap(l.sample)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		identity := classificationIdentity(k, k.stableID(entities[l.entity].nativeID), l.label, l.method)
		content := classificationContentHash(k, l.confidence, sample)
		// Appeared seals label and method (always) plus the sample; changed keeps
		// the identity's label and method and re-seals only the sample.
		return identity, content, 2 + optionalSeal(sample), optionalSeal(sample), nil
	})
	if err != nil {
		return 0, err
	}
	p.classAppeared, p.classChanged, p.classGone = appeared, changed, gone
	return seals, nil
}

// applyModelTables writes the permission, exposure, and classification changes
// of a later scan: appeared rows are inserted, changed rows updated, and
// disappeared rows deleted. These tables keep no history and no soft-gone state.
// w.scanID, w.entities, and w.nodeByPos are set by applyPlan.
func (w *loadWriter) applyModelTables(s laterScan, p *laterPlan) {
	base := w.nextID("permissions")
	for j, pos := range p.permAppeared {
		w.appearPermission(base+int64(j), &s.permissions[pos])
	}
	for _, ch := range p.permChanged {
		w.changePermission(ch.id, &s.permissions[ch.pos])
	}
	w.deleteByID("permissions", "permission_id", p.permGone)

	base = w.nextID("exposures")
	for j, pos := range p.exposureAppeared {
		w.appearExposure(base+int64(j), &s.exposures[pos])
	}
	for _, ch := range p.exposureChanged {
		w.changeExposure(ch.id, &s.exposures[ch.pos])
	}
	w.deleteByID("exposures", "exposure_id", p.exposureGone)

	base = w.nextID("classifications")
	for j, pos := range p.classAppeared {
		w.appearClassification(base+int64(j), &s.labels[pos])
	}
	for _, ch := range p.classChanged {
		w.changeClassification(ch.id, &s.labels[ch.pos])
	}
	w.deleteByID("classifications", "classification_id", p.classGone)
}

func (w *loadWriter) deleteByID(table, pkCol string, ids []int64) {
	if len(ids) == 0 {
		return
	}
	st := w.prep("DELETE FROM " + table + " WHERE " + pkCol + " = ?")
	for _, id := range ids {
		w.exec(st, id)
	}
}

func (w *loadWriter) appearPermission(id int64, e *permissionRecord) {
	cond, err := canonicalMap(e.condition)
	w.fail(err)
	var inheritedNode any
	var inheritedSID []byte
	if e.inheritedFrom >= 0 {
		inheritedNode = w.nodeByPos[e.inheritedFrom]
		inheritedSID = w.entitySID(e.inheritedFrom)
	}
	identity := permissionIdentity(w.k, w.entitySID(e.principal), w.entitySID(e.resource), e.action)
	content := permissionContentHash(w.k, e.effect, cond, inheritedSID)
	w.exec(w.prep(`INSERT INTO permissions (permission_id, tenant_id, permission_hash, principal, resource, action, effect,
		condition_sealed, inherited_from, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, w.k.id, identity, w.nodeByPos[e.principal], w.nodeByPos[e.resource], e.action, e.effect,
		w.sealOptional(FieldPermissionCondition(), id, cond), inheritedNode, content, w.scanID, w.scanID)
}

func (w *loadWriter) changePermission(id int64, e *permissionRecord) {
	cond, err := canonicalMap(e.condition)
	w.fail(err)
	var inheritedNode any
	var inheritedSID []byte
	if e.inheritedFrom >= 0 {
		inheritedNode = w.nodeByPos[e.inheritedFrom]
		inheritedSID = w.entitySID(e.inheritedFrom)
	}
	content := permissionContentHash(w.k, e.effect, cond, inheritedSID)
	w.exec(w.prep(`UPDATE permissions SET effect = ?, condition_sealed = ?, inherited_from = ?, content_hash = ?, last_seen_scan = ? WHERE permission_id = ?`),
		e.effect, w.sealOptional(FieldPermissionCondition(), id, cond), inheritedNode, content, w.scanID, id)
}

func (w *loadWriter) appearExposure(id int64, e *exposureRecord) {
	trace, err := canonicalMap(e.trace)
	w.fail(err)
	identity := exposureIdentity(w.k, w.entitySID(e.node), e.sourceZone, e.protocol, e.portFrom, e.portTo)
	content := exposureContentHash(w.k, e.authRequired, e.effective, trace)
	w.exec(w.prep(`INSERT INTO exposures (exposure_id, tenant_id, exposure_hash, node_id, source_zone, protocol, port_from, port_to,
		auth_required, effective, trace_sealed, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, w.k.id, identity, w.nodeByPos[e.node], e.sourceZone,
		nullIfNegative(e.protocol), nullIfNegative(e.portFrom), nullIfNegative(e.portTo),
		e.authRequired, e.effective, w.sealOptional(FieldExposureTrace(), id, trace), content, w.scanID, w.scanID)
}

func (w *loadWriter) changeExposure(id int64, e *exposureRecord) {
	trace, err := canonicalMap(e.trace)
	w.fail(err)
	content := exposureContentHash(w.k, e.authRequired, e.effective, trace)
	w.exec(w.prep(`UPDATE exposures SET auth_required = ?, effective = ?, trace_sealed = ?, content_hash = ?, last_seen_scan = ? WHERE exposure_id = ?`),
		e.authRequired, e.effective, w.sealOptional(FieldExposureTrace(), id, trace), content, w.scanID, id)
}

func (w *loadWriter) appearClassification(id int64, l *labelRecord) {
	sample, err := canonicalMap(l.sample)
	w.fail(err)
	identity := classificationIdentity(w.k, w.entitySID(l.entity), l.label, l.method)
	content := classificationContentHash(w.k, l.confidence, sample)
	w.exec(w.prep(`INSERT INTO classifications (classification_id, tenant_id, classification_hash, node_id, label_sealed, method_sealed,
		confidence, approved_sample_sealed, content_hash, first_seen_scan, last_seen_scan)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		id, w.k.id, identity, w.nodeByPos[l.entity],
		w.seal(FieldClassificationLabel(), id, []byte(l.label)), w.seal(FieldClassificationMethod(), id, []byte(l.method)),
		l.confidence, w.sealOptional(FieldClassificationSample(), id, sample), content, w.scanID, w.scanID)
}

// changeClassification updates a classification's content (confidence and the
// approved sample); its label and method are identity, so they never change on
// a change.
func (w *loadWriter) changeClassification(id int64, l *labelRecord) {
	sample, err := canonicalMap(l.sample)
	w.fail(err)
	content := classificationContentHash(w.k, l.confidence, sample)
	w.exec(w.prep(`UPDATE classifications SET confidence = ?, approved_sample_sealed = ?, content_hash = ?, last_seen_scan = ? WHERE classification_id = ?`),
		l.confidence, w.sealOptional(FieldClassificationSample(), id, sample), content, w.scanID, id)
}

// collectGoneEntities deletes entities marked gone that nothing refers to any
// more: no change record (retention has pruned them), and no current-state row
// in any table with a foreign key to entities. It runs after the scan's writes
// and retention, so an entity whose last reference the scan removed is collected
// in the same transaction (ADR-0011 §1).
func (w *loadWriter) collectGoneEntities() {
	w.exec(w.prep(`DELETE FROM entities WHERE gone_scan IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM entity_snapshots WHERE node_id = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM edges WHERE src = entities.node_id OR dst = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM permissions WHERE principal = entities.node_id OR resource = entities.node_id OR inherited_from = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM exposures WHERE node_id = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM classifications WHERE node_id = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM findings WHERE node_id = entities.node_id)
		AND NOT EXISTS (SELECT 1 FROM attack_paths WHERE entry = entities.node_id OR target = entities.node_id)`))
}
