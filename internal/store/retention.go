package store

// Retention (ADR-0011 §1). A tenant keeps only its most recent retention_scans
// scans (1..30, default 30). Deleting an older scan cascades to that scan's
// per-scan records - evidence, scopes, entity and edge change records, findings,
// and attack paths, each declared ON DELETE CASCADE - so the file stays close to
// its current-state size plus the retained window of history, rather than
// growing without bound.
//
// Current-state rows (entities, edges, permissions, exposures, classifications)
// carry no foreign key to scans, so they survive: they describe what the latest
// scan saw, not one scan's history. A gone entity (soft-marked, kept while any
// record still refers to it) is removed once retention has pruned its change
// records and its other references are gone, by collectGoneEntities, which runs
// right after this. One consequence remains, called out where it matters: a
// current-state row's evidence_id may name evidence from a scan that retention
// has pruned; evidence_id carries no foreign key, so this is allowed, and
// readers must treat missing evidence as "outside the retained window", not an
// error.

// pruneToRetention deletes every scan except the retention_scans most recent,
// in the caller's transaction, so retention is atomic with the scan that
// triggered it. It reads the window from the tenant row rather than taking it as
// an argument, so the CHECK on retention_scans (1..30) is the single source of
// truth.
func (w *loadWriter) pruneToRetention() {
	if w.err != nil {
		return
	}
	var keep int64
	w.fail(w.tx.QueryRowContext(w.ctx, "SELECT retention_scans FROM tenant WHERE singleton = 1").Scan(&keep))
	w.exec(w.prep("DELETE FROM scans WHERE scan_id NOT IN (SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT ?)"), keep)
}
