package store

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The migration gates of ADR-0012 §3. CI's "Migration gates" step runs
// TestT28ContractMigrationGate and TestExpandMigrationsAreAdditive and fails
// unless both pass.

// t28Gate is ADR-0012 §3's rule: contract migrations may ship only once a
// tenant held open by one process blocks migration by another.
func t28Gate(set *migrationSet, openBlocksMigration bool) error {
	var contracts []string
	for _, st := range set.steps {
		if st.kind == kindContract {
			contracts = append(contracts, st.String())
		}
	}
	if len(contracts) > 0 && !openBlocksMigration {
		return fmt.Errorf("contract migrations %s would ship, but a tenant held open by one process can still be migrated by another (threat T-28); contract migrations wait for the shared open lock (ADR-0012 §3)",
			strings.Join(contracts, ", "))
	}
	return nil
}

// openTenantBlocksMigration reports whether T-28's property holds: while one
// store holds a tenant open, a contract migration by another store fails with
// ErrInUse and leaves the file at its old version.
func openTenantBlocksMigration(t *testing.T) bool {
	t.Helper()
	ctx := context.Background()
	mt := newMigrationTest(t)
	holder := mt.binary(binaryAt(t, 3, nil))
	id := createTenant(t, holder)
	tn := acquire(t, holder, id)
	other := mt.binary(binaryAt(t, 4, nil))
	_, _, err := other.Acquire(ctx, id)
	closeStore(t, other)
	ident, _ := header(t, tn)
	return errors.Is(err, ErrInUse) && ident.schema == 3
}

func TestT28ContractMigrationGate(t *testing.T) {
	prod, err := productionMigrations()
	if err != nil {
		t.Fatal(err)
	}
	blocks := openTenantBlocksMigration(t)
	if err := t28Gate(prod, blocks); err != nil {
		t.Fatal(err)
	}
	if blocks {
		t.Log("a tenant held open blocks migration by another process: contract migrations may ship")
	} else {
		t.Log("gate closed: no contract migration ships, and none may until the shared open lock lands (ADR-0012 §3)")
	}
}

func TestT28GateRefusesContractMigrations(t *testing.T) {
	withContract := binaryAt(t, 4, nil)
	if err := t28Gate(withContract, false); err == nil || !strings.Contains(err.Error(), "0004_rename_body") {
		t.Errorf("a contract migration without the open lock: error = %v, want a refusal naming 0004_rename_body", err)
	}
	if err := t28Gate(withContract, true); err != nil {
		t.Errorf("a contract migration with the open lock: %v", err)
	}
	if err := t28Gate(binaryAt(t, 3, nil), false); err != nil {
		t.Errorf("expand migrations only: %v", err)
	}
}

// columnDef is one column as PRAGMA table_xinfo reports it, position included.
type columnDef struct {
	cid     int64
	typ     string
	notNull bool
	dflt    sql.NullString
	pk      int64
	hidden  int64
}

// tableDef is what the previous binary relies on in one table.
type tableDef struct {
	sql      string
	rootpage int64
	columns  map[string]columnDef
	fks      []string
	unique   map[string]bool
}

func schemaDefs(t *testing.T, db *sql.DB) map[string]tableDef {
	t.Helper()
	ctx := context.Background()
	query := func(q string, arg any, row func(*sql.Rows) error) {
		t.Helper()
		rows, err := db.QueryContext(ctx, q, arg)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			if err := row(rows); err != nil {
				t.Fatal(err)
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			t.Fatal(err)
		}
	}
	defs := map[string]tableDef{}
	query(`SELECT name, rootpage, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE ? ESCAPE '\'`, `sqlite\_%`, func(r *sql.Rows) error {
		var name, text string
		var root int64
		err := r.Scan(&name, &root, &text)
		defs[name] = tableDef{sql: text, rootpage: root, columns: map[string]columnDef{}, unique: map[string]bool{}}
		return err
	})
	for name, def := range defs {
		query(`SELECT cid, name, type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(?)`, name, func(r *sql.Rows) error {
			var col string
			var c columnDef
			err := r.Scan(&c.cid, &col, &c.typ, &c.notNull, &c.dflt, &c.pk, &c.hidden)
			def.columns[col] = c
			return err
		})
		query(`SELECT "table", "from", coalesce("to", ''), on_update, on_delete FROM pragma_foreign_key_list(?) ORDER BY id, seq`, name, func(r *sql.Rows) error {
			var target, from, to, onUpdate, onDelete string
			err := r.Scan(&target, &from, &to, &onUpdate, &onDelete)
			def.fks = append(def.fks, strings.Join([]string{from, target, to, onUpdate, onDelete}, " "))
			return err
		})
		query(`SELECT name FROM pragma_index_list(?) WHERE "unique" = 1`, name, func(r *sql.Rows) error {
			var idx string
			err := r.Scan(&idx)
			def.unique[idx] = true
			return err
		})
		defs[name] = def
	}
	return defs
}

// additiveViolations lists how after breaks what the previous binary relies
// on in before.
func additiveViolations(before, after map[string]tableDef) []string {
	var v []string
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			v = append(v, "table "+name+" was removed or renamed")
			continue
		}
		if a.rootpage != b.rootpage {
			v = append(v, "table "+name+" was rebuilt")
		}
		for col, bc := range b.columns {
			if ac, ok := a.columns[col]; !ok {
				v = append(v, "column "+name+"."+col+" was removed or renamed")
			} else if ac != bc {
				v = append(v, "column "+name+"."+col+" changed")
			}
		}
		var added []string
		byPosition := func(x, y string) int { return cmp.Compare(a.columns[x].cid, a.columns[y].cid) }
		for _, col := range slices.SortedFunc(maps.Keys(a.columns), byPosition) {
			if _, old := b.columns[col]; old {
				continue
			}
			added = append(added, col)
			if ac := a.columns[col]; ac.notNull && !ac.dflt.Valid {
				v = append(v, "new column "+name+"."+col+" is NOT NULL without a default, so the previous binary's inserts would fail")
			}
		}
		if !addedColumnsOnly(b.sql, a.sql, added) {
			v = append(v, "the definition of table "+name+" changed beyond added columns")
		}
		if !slices.Equal(a.fks, b.fks) {
			v = append(v, "the foreign keys of "+name+" changed")
		}
		for idx := range a.unique {
			if !b.unique[idx] {
				v = append(v, "unique index "+idx+" was added to existing table "+name)
			}
		}
	}
	slices.Sort(v)
	return v
}

// addedColumnsOnly reports whether after is before with only the columns
// added, in order, the way SQLite records ALTER TABLE ADD COLUMN: ", <column
// definition>" inserted at the end of the column definitions, before any
// table constraints, and nothing else changed.
func addedColumnsOnly(before, after string, added []string) bool {
	p := 0
	for p < len(before) && p < len(after) && before[p] == after[p] {
		p++
	}
	rest := before[p:]
	if len(after) < len(before) || !strings.HasSuffix(after, rest) {
		return false // text was removed or changed
	}
	inserted := strings.TrimSpace(after[p : len(after)-len(rest)])
	if len(added) == 0 {
		return inserted == ""
	}
	head, next := strings.TrimSpace(before[:p]), strings.TrimSpace(rest)
	switch {
	case strings.HasPrefix(inserted, ",") && (strings.HasPrefix(next, ")") || strings.HasPrefix(next, ",")):
		inserted = inserted[1:]
	case strings.HasSuffix(inserted, ",") && strings.HasSuffix(head, ","):
		// The shared prefix took the insertion's leading comma: the columns
		// were inserted before the table constraints.
		inserted = inserted[:len(inserted)-1]
	default:
		return false
	}
	parts := splitTopLevel(inserted)
	if len(parts) != len(added) {
		return false
	}
	for i, part := range parts {
		f := strings.Fields(part)
		if len(f) == 0 || !strings.EqualFold(unquoteIdent(f[0]), added[i]) {
			return false
		}
	}
	return true
}

// splitTopLevel splits s at the commas outside parentheses and quotes.
func splitTopLevel(s string) []string {
	var parts []string
	depth, start := 0, 0
	var closer byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case closer != 0:
			if c == closer {
				closer = 0
			}
		case c == '\'' || c == '"' || c == '`':
			closer = c
		case c == '[':
			closer = ']'
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func unquoteIdent(s string) string {
	if len(s) >= 2 && strings.ContainsRune("\"'`[", rune(s[0])) {
		return s[1 : len(s)-1]
	}
	return s
}

// expandViolations applies set's migrations in order to a fresh file and
// returns, for each expand migration, how it breaks the previous binary.
func expandViolations(t *testing.T, set *migrationSet) map[string][]string {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "additive.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	id, err := NewTenantID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, st := range set.steps {
		before := schemaDefs(t, db)
		if _, err := db.ExecContext(ctx, st.render(id)); err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		if st.kind != kindExpand {
			continue
		}
		if v := additiveViolations(before, schemaDefs(t, db)); len(v) > 0 {
			out[st.String()] = v
		}
	}
	return out
}

func TestExpandMigrationsAreAdditive(t *testing.T) {
	prod, err := productionMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if v := expandViolations(t, prod); len(v) > 0 {
		t.Fatalf("these expand migrations break the previous binary; declare them contract, which T-28 gates (ADR-0012 §3): %v", v)
	}
	if v := expandViolations(t, binaryAt(t, 3, nil)); len(v) > 0 {
		t.Fatalf("the test chain's expand migrations: %v", v)
	}
}

func TestAdditiveCheckAcceptsAddedColumns(t *testing.T) {
	for name, body := range map[string]string{
		"columns with commas in DEFAULT and CHECK": "ALTER TABLE notes ADD COLUMN a TEXT DEFAULT 'x,y';\nALTER TABLE notes ADD COLUMN b INTEGER CHECK (b IN (1, 2));",
		"a column on a table with a constraint":    "ALTER TABLE tenant ADD COLUMN note TEXT;",
		"a quoted column name":                     `ALTER TABLE notes ADD COLUMN "quoted" TEXT;`,
		"a new table and an index":                 "CREATE TABLE extra (x INTEGER) STRICT;\nCREATE INDEX notes_body ON notes (body);",
	} {
		t.Run(name, func(t *testing.T) {
			set := binaryAt(t, 2, map[string]string{"0003_additive": "-- kind: expand\n" + body + "\n"})
			if v := expandViolations(t, set); len(v) > 0 {
				t.Errorf("an additive migration was flagged: %v", v)
			}
		})
	}
}

func TestAdditiveCheckCatchesMislabelledMigrations(t *testing.T) {
	rebuild := "CREATE TABLE notes_new (\n" +
		"\tid INTEGER PRIMARY KEY,\n" +
		"\ttenant_id TEXT NOT NULL CHECK (tenant_id = '" + tenantIDPlaceholder + "'),\n" +
		"\tbody BLOB NOT NULL CHECK (length(body) > 0)%s\n" +
		") STRICT;\n" +
		"INSERT INTO notes_new (id, tenant_id, body) SELECT id, tenant_id, body FROM notes;\n" +
		"DROP TABLE notes;\n" +
		"ALTER TABLE notes_new RENAME TO notes;\n"
	for name, c := range map[string]struct {
		body string
		want string
	}{
		"dropped column":                   {"ALTER TABLE notes DROP COLUMN body;", "column notes.body was removed or renamed"},
		"renamed column":                   {"ALTER TABLE notes RENAME COLUMN body TO sealed;", "column notes.body was removed or renamed"},
		"dropped table":                    {"DROP TABLE note_links;", "table note_links was removed or renamed"},
		"renamed table":                    {"ALTER TABLE note_links RENAME TO links;", "table note_links was removed or renamed"},
		"rebuilt with a CHECK":             {fmt.Sprintf(rebuild, ""), "table notes was rebuilt"},
		"rebuilt with NOT NULL":            {fmt.Sprintf(rebuild, ",\n\tflag INTEGER NOT NULL"), "new column notes.flag is NOT NULL without a default"},
		"unique index added":               {"CREATE UNIQUE INDEX notes_body ON notes (body);", "unique index notes_body was added to existing table notes"},
		"foreign key re-pointed":           {"DROP TABLE note_links;\nCREATE TABLE note_links (note_id INTEGER NOT NULL REFERENCES notes (rowid)) STRICT;", "the foreign keys of note_links changed"},
		"recreated with a CHECK":           {"DROP TABLE note_links;\nCREATE TABLE note_links (note_id INTEGER NOT NULL CHECK (note_id > 0) REFERENCES notes (id)) STRICT;", "the definition of table note_links changed"},
		"recreated with a table CHECK":     {"DROP TABLE note_links;\nCREATE TABLE note_links (note_id INTEGER NOT NULL REFERENCES notes (id), flag INTEGER, CHECK (note_id > 0)) STRICT;", "the definition of table note_links changed"},
		"recreated with a column inserted": {"DROP TABLE note_links;\nCREATE TABLE note_links (flag INTEGER, note_id INTEGER NOT NULL REFERENCES notes (id)) STRICT;", "column note_links.note_id changed"},
	} {
		t.Run(name, func(t *testing.T) {
			set := binaryAt(t, 2, map[string]string{"0003_mislabelled": "-- kind: expand\n" + c.body + "\n"})
			v := expandViolations(t, set)["0003_mislabelled"]
			if !slices.ContainsFunc(v, func(s string) bool { return strings.Contains(s, c.want) }) {
				t.Errorf("violations %q, want one containing %q", v, c.want)
			}
		})
	}
}
