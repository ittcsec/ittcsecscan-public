package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Invariants of the canonical schema (ADR-0011 §4), checked over every table
// in a new tenant file, so a table added later is covered without a new test.

// userTables lists the file's own tables, in name order.
func userTables(ctx context.Context, c *sql.Conn) ([]string, error) {
	rows, err := c.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// populateEveryTable gives every table of a new tenant rows: the initial
// load, then one row in each table it does not write.
func populateEveryTable(t *testing.T, tn *Tenant) {
	t.Helper()
	if _, err := tn.loadFirstScan(context.Background(), syntheticScan(t, 20, 3, 5, 3)); err != nil {
		t.Fatal(err)
	}
	id := tn.ID().String()
	for _, stmt := range []string{
		"INSERT INTO scopes (tenant_id, scan_id, provider, account_sealed, requested, observed, completeness) VALUES (?, 1, 1, x'00', 1, 1, 1)",
		"INSERT INTO entity_snapshots (tenant_id, scan_id, node_id, change, schema_version, content_hash) VALUES (?, 1, 1, 2, 1, zeroblob(32))",
		"INSERT INTO edge_snapshots (tenant_id, scan_id, edge_id, change, src, kind, dst, content_hash) VALUES (?, 1, 1, 2, 1, 1, 2, zeroblob(32))",
		"INSERT INTO permissions (tenant_id, permission_hash, principal, resource, action, effect, content_hash, first_seen_scan, last_seen_scan) VALUES (?, zeroblob(32), 1, 2, 's3:GetObject', 1, zeroblob(32), 1, 1)",
		"INSERT INTO exposures (tenant_id, exposure_hash, node_id, source_zone, protocol, port_from, port_to, auth_required, effective, content_hash, first_seen_scan, last_seen_scan) VALUES (?, zeroblob(32), 1, 1, 6, 443, 443, 0, 1, zeroblob(32), 1, 1)",
		"INSERT INTO rules (tenant_id, rule_id, version, pack_id, severity_model, input_contract) VALUES (?, 'rule', '1', 'pack', 'model', '{}')",
		"INSERT INTO findings (tenant_id, scan_id, rule_row, node_id, finding_hash, state, status, risk, confidence, first_seen_at) VALUES (?, 1, 1, 1, zeroblob(32), 2, 1, 10, 90, 0)",
		"INSERT INTO attack_paths (tenant_id, scan_id, entry, target, score, confidence, steps_sealed) VALUES (?, 1, 1, 2, 5, 80, x'00')",
		"INSERT INTO path_steps (path_id, sequence, tenant_id, node_id, edge_id, technique_id) VALUES (1, 0, ?, 1, 1, 'T1078')",
		"INSERT INTO cut_sets (tenant_id, scan_id, change_set_sealed, paths_removed, risk_reduction, effort, disruption) VALUES (?, 1, x'00', 1, 5, 1, 0)",
		"INSERT INTO remediation_plans (tenant_id, finding_id, state_hash, actions_sealed, preconditions_sealed, rollback_sealed, created_at) VALUES (?, 1, zeroblob(32), x'00', x'00', x'00', 0)",
		"INSERT INTO criticality_overrides (tenant_id, stable_id, criticality, actor_sealed, created_at) VALUES (?, zeroblob(32), 1, x'00', 0)",
		"INSERT INTO remediation_receipts (tenant_id, stable_id, rule, plan_hash, profile, action, applied, created_at) VALUES (?, zeroblob(32), 'r', 'h', 'remediation', 'a', 1, 0)",
	} {
		execArgs(t, tn, stmt, id)
	}
}

// Every table carries tenant_id, and the file refuses any other tenant's,
// whatever code writes the row (ADR-0011 §4, owner decision 2026-09-13).
func TestEveryTableRefusesAnotherTenantsRows(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	id, other := createTenant(t, s), createTenant(t, s)
	tn := acquire(t, s, id)
	populateEveryTable(t, tn)
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		tables, err := userTables(ctx, c)
		if err != nil {
			return err
		}
		if len(tables) != 20 {
			t.Errorf("%d tables: %v", len(tables), tables)
		}
		for _, table := range tables {
			var typ, text string
			var notNull, rows int
			err := c.QueryRowContext(ctx, `SELECT p.type, p."notnull", m.sql, (SELECT 0) FROM sqlite_schema AS m, pragma_table_xinfo(m.name) AS p
				WHERE m.name = ? AND p.name = 'tenant_id'`, table).Scan(&typ, &notNull, &text, &rows)
			if err != nil {
				t.Errorf("%s has no tenant_id column (%v)", table, err)
				continue
			}
			if typ != "TEXT" || notNull != 1 || !strings.Contains(text, "CHECK (tenant_id = '"+id.String()+"')") {
				t.Errorf("%s.tenant_id is %s, not null %d, and its definition lacks the file's CHECK", table, typ, notNull)
			}
			if err := c.QueryRowContext(ctx, `SELECT count(*) FROM "`+table+`"`).Scan(&rows); err != nil || rows == 0 {
				t.Errorf("%s holds no rows to test (%v): add one to populateEveryTable", table, err)
				continue
			}
			_, err = c.ExecContext(ctx, `UPDATE "`+table+`" SET tenant_id = ?`, other.String()) //nolint:gosec // G202: as above
			if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
				t.Errorf("%s accepted another tenant's ID: %v", table, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// tenant_id is the key of no index, so the planner can never again choose
// a tenant_id prefix (ADR-0011 §4, decision 3). A WITHOUT ROWID table's
// primary key is the table itself and stores every column, but not as a key.
func TestNoIndexContainsTenantID(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, `SELECT m.name, l.name FROM sqlite_schema AS m, pragma_index_list(m.name) AS l, pragma_index_xinfo(l.name) AS x
			WHERE m.type = 'table' AND x.name = 'tenant_id' AND x.key = 1`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var table, index string
			if err := rows.Scan(&table, &index); err != nil {
				return err
			}
			t.Errorf("index %s on %s contains tenant_id", index, table)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// pinnedPlans are the exact query plans of the hot queries (ADR-0011 §4,
// decision 5). A change fails CI, and the plans must then be re-examined,
// not re-pinned.
var pinnedPlans = map[string]string{
	sqlGraphEdges:     "SCAN edges USING COVERING INDEX edges_out",
	sqlOutNeighbours:  "SEARCH edges USING COVERING INDEX edges_out (src=?)",
	sqlInNeighbours:   "SEARCH edges USING COVERING INDEX edges_in (dst=?)",
	sqlNodeByStableID: "SEARCH entities USING COVERING INDEX entities_stable_id (stable_id=?)",
	sqlFindingsByNode: "SEARCH findings USING COVERING INDEX findings_node (node_id=?)",
	sqlLabels:         "SCAN classifications",
}

func explain(ctx context.Context, c *sql.Conn, query string) (string, error) {
	// Parameters must be bound even to explain a query; their values do not
	// change the plan's shape.
	rows, err := c.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, make([]any, strings.Count(query, "?"))...)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			return "", err
		}
		steps = append(steps, detail)
	}
	return strings.Join(steps, "; "), rows.Err()
}

var indexedLookup = regexp.MustCompile(`^SEARCH (\S+) USING (COVERING INDEX \S+|INDEX \S+|PRIMARY KEY) \((\S+)=\?\)$`)

// planProblems checks every pinned hot-query plan, and that every foreign
// key's child lookup, which cascades and parent deletes run, uses an index.
func planProblems(ctx context.Context, c *sql.Conn) ([]string, int, error) {
	var problems []string
	for q, want := range pinnedPlans {
		got, err := explain(ctx, c, q)
		if err != nil {
			return nil, 0, err
		}
		if got != want {
			problems = append(problems, fmt.Sprintf("%s\n    plan %q\n    want %q", q, got, want))
		}
	}
	rows, err := c.QueryContext(ctx, `SELECT m.name, f."from" FROM sqlite_schema AS m, pragma_foreign_key_list(m.name) AS f WHERE m.type = 'table' ORDER BY 1, 2`)
	if err != nil {
		return nil, 0, err
	}
	var lookups [][2]string
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			return nil, 0, errors.Join(err, rows.Close())
		}
		lookups = append(lookups, [2]string{table, col})
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, 0, err
	}
	for _, l := range lookups {
		got, err := explain(ctx, c, `SELECT 1 FROM "`+l[0]+`" WHERE "`+l[1]+`" = ?`)
		if err != nil {
			return nil, 0, err
		}
		if m := indexedLookup.FindStringSubmatch(got); m == nil || m[1] != l[0] || m[3] != l[1] {
			problems = append(problems, fmt.Sprintf("the foreign key %s.%s is looked up without an index: %q", l[0], l[1], got))
		}
	}
	return problems, len(lookups), nil
}

// The pinned plans hold with statistics from real data (the small-business
// profile, 2,000 entities) and with no statistics at all.
func TestQueryPlansArePinned(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	if _, err := tn.loadFirstScan(ctx, syntheticScan(t, 2000, 10, 10, 11)); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []struct {
		name  string
		setup string
	}{
		{"with statistics", ""},
		{"without statistics", "DELETE FROM sqlite_stat1; ANALYZE sqlite_schema"},
	} {
		err := tn.withConn(ctx, func(c *sql.Conn) error {
			if phase.setup != "" {
				if _, err := c.ExecContext(ctx, phase.setup); err != nil {
					return err
				}
			}
			var stats int
			if err := c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_stat1").Scan(&stats); err != nil {
				return err
			}
			if (stats > 0) != (phase.setup == "") {
				return fmt.Errorf("%d statistics rows %s", stats, phase.name)
			}
			problems, fks, err := planProblems(ctx, c)
			if err != nil {
				return err
			}
			if fks < 20 {
				t.Errorf("only %d foreign keys checked", fks)
			}
			for _, p := range problems {
				t.Errorf("%s: %s", phase.name, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
