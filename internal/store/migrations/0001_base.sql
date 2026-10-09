-- kind: base
-- The tenant file's header: its identity row (master plan §5 tenants, one row
-- per file, ADR-0010 §1) and the record of applied migrations (ADR-0011 §2).
-- Every binary, old or new, reads both tables to decide whether it may open
-- the file, so neither may ever change incompatibly. Like every table, both
-- carry tenant_id, and the file refuses any other tenant's (ADR-0011 §4).
CREATE TABLE tenant (
	singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
	tenant_id          TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	created_at         TEXT    NOT NULL,
	schema_version     INTEGER NOT NULL,
	min_reader_version INTEGER NOT NULL,
	key_generation     INTEGER NOT NULL,
	wrapped_data_key   BLOB    NOT NULL,
	wrapped_id_key     BLOB    NOT NULL,
	CHECK (min_reader_version BETWEEN 1 AND schema_version)
) STRICT;

CREATE TABLE schema_migrations (
	number     INTEGER PRIMARY KEY CHECK (number >= 1),
	tenant_id  TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	name       TEXT    NOT NULL,
	sha256     TEXT    NOT NULL CHECK (length(sha256) = 64),
	applied_by TEXT    NOT NULL,
	applied_at TEXT    NOT NULL
) STRICT;
