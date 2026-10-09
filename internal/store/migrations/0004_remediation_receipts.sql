-- kind: expand
-- Remediation receipts (master plan Prompt 13; ADR-0029): an append-only, immutable
-- record of every executed remediation, written at the point of verification. Each row
-- records which finding rule and plan hash was applied, under which credential profile,
-- the smallest action taken, whether it was applied or refused, and, sealed with the
-- tenant data key, the resource's prior state (captured before the change, so an operator
-- can restore it) and any refusal reason. Rows are only ever inserted, never updated or
-- deleted, so the audit trail is immutable and survives retention. prior_state_sealed and
-- refusal_sealed are sealed and bound to the row's receipt_id (ADR-0011 §3, ADR-0013). The
-- log carries no scan foreign key, for the same reason the criticality override log does
-- not: the history must outlive any single scan.
CREATE TABLE remediation_receipts (
	receipt_id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id          TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	stable_id          BLOB    NOT NULL CHECK (length(stable_id) = 32),
	rule               TEXT    NOT NULL,
	plan_hash          TEXT    NOT NULL,
	profile            TEXT    NOT NULL,
	action             TEXT    NOT NULL,
	applied            INTEGER NOT NULL CHECK (applied IN (0, 1)),
	prior_state_sealed BLOB,
	refusal_sealed     BLOB,
	created_at         INTEGER NOT NULL
) STRICT;
CREATE INDEX remediation_receipts_entity ON remediation_receipts (stable_id, receipt_id);
