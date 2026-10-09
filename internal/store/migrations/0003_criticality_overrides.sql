-- kind: expand
-- Business-criticality overrides (ADR-0025 §4): an append-only, audited log of
-- human criticality decisions. Each row records who set it (actor_sealed), when
-- (created_at, Unix milliseconds UTC), why (reason_sealed), and the level, keyed to
-- the target entity by its tenant-scoped stable id. The log carries no scan foreign
-- key, so the full audit history survives retention; the highest override_id per
-- stable_id is the effective override. Rows are only ever inserted, never updated or
-- deleted, so the history is intact. actor_sealed and reason_sealed are sealed with
-- the tenant data key, bound to the row's override_id, for the same at-rest
-- protection every other human-supplied value gets (ADR-0011 §3, ADR-0013).
CREATE TABLE criticality_overrides (
	override_id   INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	stable_id     BLOB    NOT NULL CHECK (length(stable_id) = 32),
	criticality   INTEGER NOT NULL CHECK (criticality >= 1),
	actor_sealed  BLOB    NOT NULL,
	reason_sealed BLOB,
	created_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX criticality_overrides_entity ON criticality_overrides (stable_id, override_id);
