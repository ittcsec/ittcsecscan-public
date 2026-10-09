-- kind: expand
-- The version-1 canonical schema (master plan §5, ADR-0011, ADR-0013).
--
-- Conventions, kept by every later migration:
-- - Every table carries tenant_id, and the file refuses any other tenant's
--   (ADR-0011 §4). No index contains tenant_id.
-- - Surrogate keys are INTEGER PRIMARY KEY AUTOINCREMENT, so no key is ever
--   reused. A sealed value is bound to its row's key and to its field's
--   logical name, never to a physical table or column name (ADR-0013).
-- - Columns ending in _sealed hold values sealed with the tenant's data key
--   (ADR-0011 §3). Columns ending in _hash hold 32-byte HMACs under the
--   tenant's stable-ID key, separated by purpose (ADR-0013); stable_id is one
--   too. Every other column is plaintext by decision.
-- - Types, kinds, and states are small integer codes (codes.go); 0 is never
--   a code. Tri-states are 0 no, 1 yes, 2 unknown. Times are Unix
--   milliseconds, UTC. Confidence is 0 to 100.
-- - Current-state tables (entities, edges, permissions, exposures,
--   classifications) describe what the latest scan saw, with the scans that
--   first and last saw each row. Those scan numbers carry no foreign key:
--   they outlive the scans they name. An entity stays, marked gone, while
--   retained records refer to it. History is change records only
--   (entity_snapshots, edge_snapshots; ADR-0011 §1).
-- - Per-scan records are deleted with their scan (ON DELETE CASCADE), and
--   every foreign key is indexed, so neither retention nor a parent delete
--   ever scans a whole table.

ALTER TABLE tenant ADD COLUMN display_name_sealed BLOB;
ALTER TABLE tenant ADD COLUMN retention_scans INTEGER NOT NULL DEFAULT 30 CHECK (retention_scans BETWEEN 1 AND 30);
-- The count of encryptions committed under this tenant's data key (B-6,
-- ADR-0011 §3). It only ever increases: slots are reserved and committed
-- before the encryptions they authorise, so a rolled-back write cannot lower
-- it. When it reaches the hard stop the key must be rotated.
ALTER TABLE tenant ADD COLUMN data_key_seal_count INTEGER NOT NULL DEFAULT 0 CHECK (data_key_seal_count >= 0);

CREATE TABLE scans (
	scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id       TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	started_at      INTEGER NOT NULL,
	completed_at    INTEGER,
	tool_version    TEXT    NOT NULL,
	status          INTEGER NOT NULL CHECK (status > 0),
	manifest_sealed BLOB    NOT NULL,
	manifest_hash   BLOB    NOT NULL CHECK (length(manifest_hash) = 32),
	-- A completed scan has a completion time. 2 is "completed" in codes.go.
	CHECK (status <> 2 OR completed_at IS NOT NULL)
) STRICT;

CREATE TABLE scopes (
	scope_id       INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id      TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id        INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	provider       INTEGER NOT NULL CHECK (provider > 0),
	account_sealed BLOB    NOT NULL,
	region_sealed  BLOB,
	requested      INTEGER NOT NULL CHECK (requested >= 0),
	observed       INTEGER NOT NULL CHECK (observed >= 0),
	completeness   INTEGER NOT NULL CHECK (completeness > 0),
	-- reason distinguishes why coarse completeness is not "complete": a pinned
	-- scope-reason code (denied, unsupported, error), NULL when complete or
	-- partial. The coarse completeness code answers whether coverage is
	-- trustworthy; reason answers why it is not, without a free-text field.
	reason         INTEGER CHECK (reason IS NULL OR reason > 0)
) STRICT;
CREATE INDEX scopes_scan ON scopes (scan_id);

-- Evidence of one scan. A current-state row names the evidence of the latest
-- scan that saw it, by evidence_id and with no foreign key. Retention (ADR-0011
-- §1) may prune that scan, so a reader that finds no evidence for an evidence_id
-- must treat it as outside the retained window, not an error.
CREATE TABLE evidence (
	evidence_id           INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id             TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id               INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	collector             TEXT    NOT NULL,
	api                   TEXT    NOT NULL,
	observed_at           INTEGER NOT NULL,
	redacted_value_sealed BLOB,
	value_hash            BLOB    NOT NULL CHECK (length(value_hash) = 32),
	freshness             INTEGER NOT NULL CHECK (freshness > 0),
	completeness          INTEGER NOT NULL CHECK (completeness > 0)
) STRICT;
CREATE INDEX evidence_scan ON evidence (scan_id);

-- The graph's nodes. node_id is file-local and never exported; stable_id is
-- the tenant-scoped identity (ADR-0010 §2) and replaces §5's native_id_hash.
CREATE TABLE entities (
	node_id           INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id         TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	stable_id         BLOB    NOT NULL CHECK (length(stable_id) = 32),
	provider          INTEGER NOT NULL CHECK (provider > 0),
	type              INTEGER NOT NULL CHECK (type > 0),
	native_id_sealed  BLOB    NOT NULL,
	name_sealed       BLOB,
	tags_sealed       BLOB,
	attributes_sealed BLOB,
	criticality       INTEGER NOT NULL DEFAULT 0 CHECK (criticality >= 0),
	content_hash      BLOB    NOT NULL CHECK (length(content_hash) = 32),
	first_seen_scan   INTEGER NOT NULL,
	last_seen_scan    INTEGER NOT NULL,
	gone_scan         INTEGER,
	first_seen_at     INTEGER NOT NULL,
	last_seen_at      INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX entities_stable_id ON entities (stable_id);
-- Gone entities are the few awaiting collection once nothing refers to them
-- (ADR-0011 §1); a partial index keeps that sweep off the whole table.
CREATE INDEX entities_gone ON entities (gone_scan) WHERE gone_scan IS NOT NULL;

CREATE TABLE entity_snapshots (
	snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id      TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id        INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	node_id        INTEGER NOT NULL REFERENCES entities (node_id),
	change         INTEGER NOT NULL CHECK (change > 0),
	schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
	content_sealed BLOB,
	content_hash   BLOB    NOT NULL CHECK (length(content_hash) = 32)
) STRICT;
CREATE UNIQUE INDEX entity_snapshots_scan ON entity_snapshots (scan_id, node_id);
CREATE INDEX entity_snapshots_node ON entity_snapshots (node_id, scan_id);

-- The graph's edges, one per source, kind, and target: alternative grants
-- are merged into conditions, and their detail lives in permissions. A gone
-- edge is deleted, and edge_snapshots keeps its record. The two covering
-- indexes answer traversal in both directions without touching the table
-- (ADR-0011 §4). An edge may lead from an entity to itself, such as a role
-- that trusts itself: that is a finding, not an error.
CREATE TABLE edges (
	edge_id           INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id         TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	src               INTEGER NOT NULL REFERENCES entities (node_id),
	kind              INTEGER NOT NULL CHECK (kind > 0),
	dst               INTEGER NOT NULL REFERENCES entities (node_id),
	conditions_sealed BLOB,
	confidence        INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
	evidence_id       INTEGER NOT NULL,
	observed_at       INTEGER NOT NULL,
	content_hash      BLOB    NOT NULL CHECK (length(content_hash) = 32),
	first_seen_scan   INTEGER NOT NULL,
	last_seen_scan    INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX edges_out ON edges (src, kind, dst);
CREATE INDEX edges_in ON edges (dst, kind, src);

-- Change records for edges. They copy the edge's endpoints, which are never
-- reused, so they need no foreign key to an edge that may be gone.
CREATE TABLE edge_snapshots (
	snapshot_id       INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id         TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id           INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	edge_id           INTEGER NOT NULL,
	change            INTEGER NOT NULL CHECK (change > 0),
	src               INTEGER NOT NULL,
	kind              INTEGER NOT NULL CHECK (kind > 0),
	dst               INTEGER NOT NULL,
	conditions_sealed BLOB,
	content_hash      BLOB    NOT NULL CHECK (length(content_hash) = 32)
) STRICT;
CREATE UNIQUE INDEX edge_snapshots_scan ON edge_snapshots (scan_id, edge_id);

CREATE TABLE permissions (
	permission_id    INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id        TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	permission_hash  BLOB    NOT NULL CHECK (length(permission_hash) = 32),
	principal        INTEGER NOT NULL REFERENCES entities (node_id),
	resource         INTEGER NOT NULL REFERENCES entities (node_id),
	action           TEXT    NOT NULL,
	effect           INTEGER NOT NULL CHECK (effect > 0),
	condition_sealed BLOB,
	inherited_from   INTEGER REFERENCES entities (node_id),
	content_hash     BLOB    NOT NULL CHECK (length(content_hash) = 32),
	first_seen_scan  INTEGER NOT NULL,
	last_seen_scan   INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX permissions_identity ON permissions (permission_hash);
CREATE INDEX permissions_principal ON permissions (principal, action);
CREATE INDEX permissions_resource ON permissions (resource);
CREATE INDEX permissions_inherited ON permissions (inherited_from);

-- Effective reachability. protocol is an IANA protocol number, or NULL for
-- any protocol. A port range has both ends or neither, and neither means
-- every port: a CHECK that evaluates to NULL passes, so the table-level
-- CHECK below refuses a half-open range.
CREATE TABLE exposures (
	exposure_id     INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id       TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	exposure_hash   BLOB    NOT NULL CHECK (length(exposure_hash) = 32),
	node_id         INTEGER NOT NULL REFERENCES entities (node_id),
	source_zone     INTEGER NOT NULL CHECK (source_zone > 0),
	protocol        INTEGER CHECK (protocol BETWEEN 0 AND 255),
	port_from       INTEGER CHECK (port_from BETWEEN 0 AND 65535),
	port_to         INTEGER CHECK (port_to BETWEEN 0 AND 65535 AND port_to >= port_from),
	auth_required   INTEGER NOT NULL CHECK (auth_required IN (0, 1, 2)),
	effective       INTEGER NOT NULL CHECK (effective IN (0, 1, 2)),
	trace_sealed    BLOB,
	content_hash    BLOB    NOT NULL CHECK (length(content_hash) = 32),
	first_seen_scan INTEGER NOT NULL,
	last_seen_scan  INTEGER NOT NULL,
	CHECK ((port_from IS NULL) = (port_to IS NULL))
) STRICT;
CREATE UNIQUE INDEX exposures_identity ON exposures (exposure_hash);
CREATE INDEX exposures_node ON exposures (node_id);

-- Labels mark the attack targets; the graph load decrypts one per
-- classified node (ADR-0011 §3).
CREATE TABLE classifications (
	classification_id      INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id              TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	classification_hash    BLOB    NOT NULL CHECK (length(classification_hash) = 32),
	node_id                INTEGER NOT NULL REFERENCES entities (node_id),
	label_sealed           BLOB    NOT NULL,
	method_sealed          BLOB    NOT NULL,
	confidence             INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
	approved_sample_sealed BLOB,
	content_hash           BLOB    NOT NULL CHECK (length(content_hash) = 32),
	first_seen_scan        INTEGER NOT NULL,
	last_seen_scan         INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX classifications_identity ON classifications (classification_hash);
CREATE INDEX classifications_node ON classifications (node_id);

-- Rules are public pack content, stored so each finding names the exact
-- rule version it came from.
CREATE TABLE rules (
	rule_row       INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id      TEXT NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	rule_id        TEXT NOT NULL,
	version        TEXT NOT NULL,
	pack_id        TEXT NOT NULL,
	severity_model TEXT NOT NULL,
	input_contract TEXT NOT NULL,
	remediation_id TEXT
) STRICT;
CREATE UNIQUE INDEX rules_version ON rules (rule_id, version);

-- state is the rule outcome (pass, fail, unknown, error, not applicable);
-- status is the finding's lifecycle. finding_hash identifies the same
-- finding across scans.
CREATE TABLE findings (
	finding_id    INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id     TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id       INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	rule_row      INTEGER NOT NULL REFERENCES rules (rule_row),
	node_id       INTEGER NOT NULL REFERENCES entities (node_id),
	finding_hash  BLOB    NOT NULL CHECK (length(finding_hash) = 32),
	state         INTEGER NOT NULL CHECK (state > 0),
	status        INTEGER NOT NULL CHECK (status > 0),
	risk          INTEGER NOT NULL CHECK (risk >= 0),
	confidence    INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
	first_seen_at INTEGER NOT NULL,
	detail_sealed BLOB
) STRICT;
CREATE UNIQUE INDEX findings_scan ON findings (scan_id, finding_hash);
CREATE INDEX findings_node ON findings (node_id);
CREATE INDEX findings_rule ON findings (rule_row);

CREATE TABLE attack_paths (
	path_id      INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id    TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id      INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	entry        INTEGER NOT NULL REFERENCES entities (node_id),
	target       INTEGER NOT NULL REFERENCES entities (node_id),
	score        INTEGER NOT NULL CHECK (score >= 0),
	confidence   INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
	steps_sealed BLOB    NOT NULL
) STRICT;
CREATE INDEX attack_paths_scan ON attack_paths (scan_id);
CREATE INDEX attack_paths_entry ON attack_paths (entry);
CREATE INDEX attack_paths_target ON attack_paths (target);

-- edge_id names an edge that may since be gone; it is never reused.
CREATE TABLE path_steps (
	path_id      INTEGER NOT NULL REFERENCES attack_paths (path_id) ON DELETE CASCADE,
	sequence     INTEGER NOT NULL CHECK (sequence >= 0),
	tenant_id    TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	node_id      INTEGER NOT NULL REFERENCES entities (node_id),
	edge_id      INTEGER,
	technique_id TEXT,
	PRIMARY KEY (path_id, sequence)
) STRICT, WITHOUT ROWID;
CREATE INDEX path_steps_node ON path_steps (node_id);

CREATE TABLE cut_sets (
	cut_id            INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id         TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	scan_id           INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
	change_set_sealed BLOB    NOT NULL,
	paths_removed     INTEGER NOT NULL CHECK (paths_removed >= 0),
	risk_reduction    INTEGER NOT NULL CHECK (risk_reduction >= 0),
	effort            INTEGER NOT NULL CHECK (effort >= 0),
	disruption        INTEGER NOT NULL CHECK (disruption >= 0)
) STRICT;
CREATE INDEX cut_sets_scan ON cut_sets (scan_id);

-- An approved plan outlives the finding it was made for: when the finding's
-- scan expires, finding_id becomes NULL and the plan stays.
CREATE TABLE remediation_plans (
	plan_id              INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id            TEXT    NOT NULL CHECK (tenant_id = '{{tenant_id}}'),
	finding_id           INTEGER REFERENCES findings (finding_id) ON DELETE SET NULL,
	state_hash           BLOB    NOT NULL CHECK (length(state_hash) = 32),
	actions_sealed       BLOB    NOT NULL,
	preconditions_sealed BLOB    NOT NULL,
	approvals_sealed     BLOB,
	rollback_sealed      BLOB    NOT NULL,
	created_at           INTEGER NOT NULL
) STRICT;
CREATE INDEX remediation_plans_finding ON remediation_plans (finding_id);
