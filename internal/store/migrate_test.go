package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/version"
)

// shippedMigrations pins every production migration's checksum. A migration
// is never edited once a release has shipped it (ADR-0011 §2): a change fails
// here, and the fix is a new migration. A new migration's checksum is added
// here in the same review. No release has shipped a tenant schema yet
// (ADR-0012 §4), which is the only reason 0001 could still gain its tenant_id
// checks on 2026-09-13; the first release that links the store freezes it
// with its release fixture.
var shippedMigrations = []string{
	"0001_base 480091251e720e91d939599a77bdfc32f4204a1279ffcebfb234a58539a3e38b",
	"0002_canonical_v1 03b02f7bb57b8a1fb2b64a7842a3edf76948a2a2c0afd73d9f32dd8c42c86f4d",
	"0003_criticality_overrides 15a2fee833335ebc13aea7ec0b3c40f98205cba9e0a78974effbe8ce1edf3c4e",
	"0004_remediation_receipts e00b86266829de4f5e55f1a2a284f0c705d3783f04622682f00ddf29619c96d0",
}

// testChain holds test-only migrations 0002 to 0004 on top of the production
// base. A test binary "at version v" ships the base and those up to v.
var testChain = map[string]string{
	"0002_notes": "-- kind: expand\n" +
		"CREATE TABLE notes (\n" +
		"\tid        INTEGER PRIMARY KEY,\n" +
		"\ttenant_id TEXT NOT NULL CHECK (tenant_id = '" + tenantIDPlaceholder + "'),\n" +
		"\tbody      BLOB NOT NULL\n" +
		") STRICT;\n" +
		"CREATE TABLE note_links (note_id INTEGER NOT NULL REFERENCES notes (id)) STRICT;\n",
	"0003_note_tags": "-- kind: expand\n" +
		"ALTER TABLE notes ADD COLUMN tag TEXT;\n" +
		"CREATE INDEX notes_tag ON notes (tag);\n",
	"0004_rename_body": "-- kind: contract\n" +
		"ALTER TABLE notes RENAME COLUMN body TO sealed;\n",
}

// migrationsFor builds a migration set from the production base plus files.
func migrationsFor(t *testing.T, files map[string]string) *migrationSet {
	t.Helper()
	base, err := embeddedMigrations.ReadFile("migrations/0001_base.sql")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"m/0001_base.sql": {Data: base}}
	for name, body := range files {
		fsys["m/"+name+".sql"] = &fstest.MapFile{Data: []byte(body)}
	}
	set, err := loadMigrations(fsys, "m")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// binaryAt is the migration set of a test binary at schema version v, plus
// any extra migration files.
func binaryAt(t *testing.T, v int64, extra map[string]string) *migrationSet {
	t.Helper()
	files := map[string]string{}
	for name, body := range testChain {
		if n, _ := strconv.ParseInt(name[:4], 10, 64); n <= v {
			files[name] = body
		}
	}
	maps.Copy(files, extra)
	return migrationsFor(t, files)
}

// migrationTest is one data directory, opened in turn by test binaries at
// different schema versions, the way successive releases would open it.
type migrationTest struct {
	t    *testing.T
	opts Options
}

func newMigrationTest(t *testing.T) *migrationTest {
	return &migrationTest{t: t, opts: Options{DataDir: testDataDir(t), Keys: staticKeys(t, testMasterKey(t, 1))}}
}

// binary opens the data directory as a binary shipping set would. Close it
// before another binary opens the same tenant.
func (m *migrationTest) binary(set *migrationSet) *Store {
	s := openStore(m.t, m.opts)
	s.migrations = set
	return s
}

func closeStore(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func execArgs(t *testing.T, tn *Tenant, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		_, err := c.ExecContext(ctx, query, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// fieldTestNote is the test chain's sealed field. Test migration 0004
// renames its column, and the value still opens: a sealed value is bound to
// its field's logical name, not to a column (ADR-0013).
var fieldTestNote = Field{"test.note"}

// addNote writes a sealed note into column col: "body" before migration
// 0004 renames it, "sealed" after.
func addNote(t *testing.T, tn *Tenant, id int64, col, text string) {
	t.Helper()
	sealed, err := tn.SealValue(fieldTestNote, id, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	insert := map[string]string{
		"body":   "INSERT INTO notes (id, tenant_id, body) VALUES (?, ?, ?)",
		"sealed": "INSERT INTO notes (id, tenant_id, sealed) VALUES (?, ?, ?)",
	}[col]
	execArgs(t, tn, insert, id, tn.ID().String(), sealed)
}

// readNotes decrypts every note, by ID.
func readNotes(t *testing.T, tn *Tenant, col string) map[int64]string {
	t.Helper()
	ctx := context.Background()
	query := map[string]string{
		"body":   "SELECT id, body FROM notes ORDER BY id",
		"sealed": "SELECT id, sealed FROM notes ORDER BY id",
	}[col]
	out := map[int64]string{}
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id int64
			var sealed []byte
			if err := rows.Scan(&id, &sealed); err != nil {
				return err
			}
			pt, err := tn.OpenValue(fieldTestNote, id, sealed)
			if err != nil {
				return err
			}
			out[id] = string(pt)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func header(t *testing.T, tn *Tenant) (identity, []recordedMigration) {
	t.Helper()
	ctx := context.Background()
	var ident identity
	var history []recordedMigration
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		var err error
		ident, history, err = readHeader(ctx, c)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ident, history
}

func foreignKeysOn(t *testing.T, tn *Tenant) bool {
	t.Helper()
	ctx := context.Background()
	var on int64
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&on)
	})
	if err != nil {
		t.Fatal(err)
	}
	return on == 1
}

// answers are the results of fixed fixture queries that a migration must not
// change.
type answers struct {
	tenantID    string
	generation  uint32
	wrappedData []byte
	wrappedID   []byte
	stableID    string
	notes       map[int64]string
}

func fixtureAnswers(t *testing.T, tn *Tenant, v int64) answers {
	t.Helper()
	ident, _ := header(t, tn)
	sid, err := tn.StableID("arn:aws:iam::123456789012:role/app")
	if err != nil {
		t.Fatal(err)
	}
	a := answers{
		tenantID: ident.tenantID, generation: ident.generation,
		wrappedData: ident.wrappedData, wrappedID: ident.wrappedID,
		stableID: sid, notes: map[int64]string{},
	}
	switch {
	case v >= 4:
		a.notes = readNotes(t, tn, "sealed")
	case v >= 2:
		a.notes = readNotes(t, tn, "body")
	}
	return a
}

// backups lists a tenant's pre-migration backups.
func backups(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(backupsPath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if backupFileName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names
}

// dump lists every schema object and every row of a closed tenant file,
// through a connection of its own.
func dump(t *testing.T, path string) string {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var b strings.Builder
	var tables []string
	rows, err := db.QueryContext(ctx, "SELECT type, name, coalesce(sql, '') FROM sqlite_schema ORDER BY type, name")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var typ, name, text string
		if err := rows.Scan(&typ, &name, &text); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s %s\n", typ, name, text)
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		rows, err := db.QueryContext(ctx, `SELECT * FROM "`+table+`" ORDER BY rowid`) //nolint:gosec // G202: table names come from the test file's own schema
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%s %v\n", table, vals)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// pageImage is a closed database file's bytes with the three header fields
// SQLite rewrites whenever it commits a restore masked: the file change
// counter (offset 24), the schema cookie (40), and version-valid-for (92).
func pageImage(t *testing.T, path string) []byte {
	t.Helper()
	b := readFile(t, path)
	if len(b) < 100 {
		t.Fatalf("%s is %d bytes, too short for a database", path, len(b))
	}
	for _, off := range []int{24, 40, 92} {
		clear(b[off : off+4])
	}
	return b
}

func TestShippedMigrationsAreUnchanged(t *testing.T) {
	set, err := productionMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, st := range set.steps {
		got = append(got, st.String()+" "+st.checksum)
	}
	if !slices.Equal(got, shippedMigrations) {
		t.Errorf("production migrations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(shippedMigrations, "\n"))
	}
}

func TestMigrationSetsAreValidated(t *testing.T) {
	base := "-- kind: base\nCREATE TABLE x (y INTEGER);\n"
	expand := "-- kind: expand\nCREATE TABLE z (y INTEGER);\n"
	for name, files := range map[string]map[string]string{
		"no migrations":        {},
		"gap":                  {"0001_base.sql": base, "0003_z.sql": expand},
		"repeated number":      {"0001_base.sql": base, "0002_a.sql": expand, "0002_b.sql": expand},
		"first is not base":    {"0001_base.sql": expand},
		"second base":          {"0001_base.sql": base, "0002_z.sql": base},
		"unknown kind":         {"0001_base.sql": base, "0002_z.sql": "-- kind: shrink\nDROP TABLE x;\n"},
		"no kind line":         {"0001_base.sql": base, "0002_z.sql": "CREATE TABLE z (y INTEGER);\n"},
		"CRLF line endings":    {"0001_base.sql": base, "0002_z.sql": "-- kind: expand\r\nCREATE TABLE z (y INTEGER);\r\n"},
		"unknown placeholder":  {"0001_base.sql": base, "0002_z.sql": "-- kind: expand\nCREATE TABLE z (y TEXT CHECK (y = '{{tenant}}'));\n"},
		"empty":                {"0001_base.sql": base, "0002_z.sql": "-- kind: expand\n\n"},
		"not UTF-8":            {"0001_base.sql": base, "0002_z.sql": "-- kind: expand\nSELECT '\xff';\n"},
		"bad file name":        {"0001_base.sql": base, "2_z.sql": expand},
		"upper-case name":      {"0001_base.sql": base, "0002_Z.sql": expand},
		"not a migration file": {"0001_base.sql": base, "README.md": "notes"},
	} {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"m": {Mode: fs.ModeDir}}
			for f, body := range files {
				fsys["m/"+f] = &fstest.MapFile{Data: []byte(body)}
			}
			if _, err := loadMigrations(fsys, "m"); err == nil {
				t.Error("the migration set was accepted")
			}
		})
	}

	// In a valid set, min_reader_version follows the last contract migration.
	set, err := loadMigrations(fstest.MapFS{
		"m/0001_base.sql": {Data: []byte(base)},
		"m/0002_z.sql":    {Data: []byte(expand)},
		"m/0003_w.sql":    {Data: []byte("-- kind: contract\nDROP TABLE z;\n")},
		"m/0004_v.sql":    {Data: []byte("-- kind: expand\nCREATE TABLE v (y INTEGER);\n")},
	}, "m")
	if err != nil {
		t.Fatal(err)
	}
	for v, want := range map[int64]int64{1: 1, 2: 1, 3: 3, 4: 3} {
		if got := set.minReaderAt(v); got != want {
			t.Errorf("minReaderAt(%d) = %d, want %d", v, got, want)
		}
	}
}

func TestCreateRecordsTheMigrationHistory(t *testing.T) {
	ctx := context.Background()
	when := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	mt := newMigrationTest(t)
	mt.opts.Now = func() time.Time { return when }
	set := binaryAt(t, 4, nil)
	s := mt.binary(set)
	id, other := createTenant(t, s), createTenant(t, s)
	tn := acquire(t, s, id)

	ident, history := header(t, tn)
	if ident.schema != 4 || ident.minReader != 4 {
		t.Errorf("schema_version %d, min_reader_version %d; want 4 and 4", ident.schema, ident.minReader)
	}
	if len(history) != len(set.steps) {
		t.Fatalf("%d migrations recorded, want %d", len(history), len(set.steps))
	}
	for i, h := range history {
		if st := set.steps[i]; h.number != st.number || h.name != st.name || h.checksum != st.checksum {
			t.Errorf("recorded %04d_%s %s, want %s %s", h.number, h.name, h.checksum, st, st.checksum)
		}
	}
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		rows, err := c.QueryContext(ctx, "SELECT applied_by, applied_at FROM schema_migrations")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var by, at string
			if err := rows.Scan(&by, &at); err != nil {
				return err
			}
			if by != version.Get().Version || at != when.Format(time.RFC3339Nano) {
				t.Errorf("applied by %q at %q, want %q at %q", by, at, version.Get().Version, when.Format(time.RFC3339Nano))
			}
		}
		var stats int
		if err := c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name = 'sqlite_stat1'").Scan(&stats); err != nil {
			return err
		}
		if stats != 1 {
			t.Error("statistics were not gathered after the migrations")
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}

	// The tenant-ID placeholder was filled in: this file refuses a row that
	// carries another tenant's ID, and accepts its own.
	err = tn.withConn(ctx, func(c *sql.Conn) error {
		_, err := c.ExecContext(ctx, "INSERT INTO notes (id, tenant_id, sealed) VALUES (1, ?, x'00')", other.String())
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Errorf("a row with another tenant's ID: error = %v, want a CHECK constraint failure", err)
	}
	addNote(t, tn, 1, "sealed", "mine")
}

// Rollback test 1, forward: a file at each earlier schema version migrates to
// the current one, and the fixture queries give the same answers.
func TestForwardMigrationKeepsAnswers(t *testing.T) {
	for from := int64(1); from < 4; from++ {
		t.Run(fmt.Sprintf("from version %d", from), func(t *testing.T) {
			mt := newMigrationTest(t)
			old := mt.binary(binaryAt(t, from, nil))
			id := createTenant(t, old)
			tn := acquire(t, old, id)
			if from >= 2 {
				addNote(t, tn, 1, "body", "first")
				addNote(t, tn, 2, "body", "second")
				execArgs(t, tn, "INSERT INTO note_links (note_id) VALUES (?)", 2)
			}
			before := fixtureAnswers(t, tn, from)
			dir := tenantDir(t, old, id)
			closeStore(t, old)

			cur := mt.binary(binaryAt(t, 4, nil))
			tn = acquire(t, cur, id)
			if after := fixtureAnswers(t, tn, 4); !reflect.DeepEqual(after, before) {
				t.Errorf("answers changed by the migration:\n got %+v\nwant %+v", after, before)
			}
			ident, history := header(t, tn)
			if ident.schema != 4 || ident.minReader != 4 || len(history) != 4 {
				t.Errorf("after migrating: schema_version %d, min_reader_version %d, %d migrations recorded", ident.schema, ident.minReader, len(history))
			}
			if !foreignKeysOn(t, tn) {
				t.Error("foreign keys are off after the migration")
			}
			names := backups(t, dir)
			if len(names) != 1 || !strings.HasPrefix(names[0], fmt.Sprintf("pre-migration-v%04d-to-v0004-", from)) {
				t.Errorf("backups %v, want one pre-migration backup from version %d", names, from)
			}
		})
	}
}

// Rollback test 1 for the production migrations: a file at every earlier
// version migrates to the latest. With only the base shipped, there is none
// yet; each migration added later is covered here automatically.
func TestProductionMigrationsMigrateFromEveryEarlierVersion(t *testing.T) {
	prod, err := productionMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if prod.latest() == 1 {
		t.Log("only the base migration ships; there is no earlier version to migrate from")
	}
	for v := int64(1); v < prod.latest(); v++ {
		t.Run(fmt.Sprintf("from version %d", v), func(t *testing.T) {
			older, err := newMigrationSet(prod.steps[:v])
			if err != nil {
				t.Fatal(err)
			}
			mt := newMigrationTest(t)
			old := mt.binary(older)
			id := createTenant(t, old)
			before := fixtureAnswers(t, acquire(t, old, id), 1)
			closeStore(t, old)

			tn := acquire(t, mt.binary(prod), id)
			if after := fixtureAnswers(t, tn, 1); !reflect.DeepEqual(after, before) {
				t.Errorf("answers changed by the migration:\n got %+v\nwant %+v", after, before)
			}
			if ident, _ := header(t, tn); ident.schema != prod.latest() {
				t.Errorf("schema_version %d, want %d", ident.schema, prod.latest())
			}
		})
	}
}

// Rollback test 2, restore: after a contract migration, restoring the backup
// gives the pre-migration file, page for page, and the previous binary opens
// it. Scans made after the migration are lost, as the operator is told.
func TestRestoreGivesThePreMigrationFile(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v3 := mt.binary(binaryAt(t, 3, nil))
	id := createTenant(t, v3)
	addNote(t, acquire(t, v3, id), 1, "body", "before the upgrade")
	dir := tenantDir(t, v3, id)
	path := dbPath(dir)
	closeStore(t, v3)
	before := dump(t, path)

	v4 := mt.binary(binaryAt(t, 4, nil))
	addNote(t, acquire(t, v4, id), 2, "sealed", "after the upgrade")
	closeStore(t, v4)
	names := backups(t, dir)
	if len(names) != 1 {
		t.Fatalf("backups %v, want exactly one", names)
	}

	// The previous binary refuses the file, and can still restore it.
	prev := mt.binary(binaryAt(t, 3, nil))
	if _, _, err := prev.Acquire(ctx, id); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("previous binary on the contracted file: error = %v, want ErrUnsupportedSchema", err)
	}
	if err := prev.restorePreMigration(ctx, id, names[0]); err != nil {
		t.Fatalf("restore: %v", err)
	}
	closeStore(t, prev)

	if after := dump(t, path); after != before {
		t.Errorf("the restored file differs from the pre-migration file:\n%s\nwant:\n%s", after, before)
	}
	if !bytes.Equal(pageImage(t, path), pageImage(t, filepath.Join(backupsPath(dir), names[0]))) {
		t.Error("the restored file is not the backup, page for page")
	}
	tn := acquire(t, mt.binary(binaryAt(t, 3, nil)), id)
	if got := readNotes(t, tn, "body"); !reflect.DeepEqual(got, map[int64]string{1: "before the upgrade"}) {
		t.Errorf("notes after the restore: %v", got)
	}
}

// A migration that fails is rolled back to the pre-migration file, even when
// an earlier migration of the same run has already committed.
func TestFailedMigrationRestoresTheFile(t *testing.T) {
	ctx := context.Background()
	for name, bad := range map[string]string{
		"SQL error after a statement succeeded": "-- kind: expand\nCREATE TABLE half_done (x INTEGER) STRICT;\nTHIS IS NOT SQL;\n",
		"foreign key violation":                 "-- kind: expand\nINSERT INTO note_links (note_id) VALUES (999);\n",
		"row with another tenant's ID":          "-- kind: expand\nINSERT INTO notes (id, tenant_id, body) VALUES (99, 'aaaaaaaaaaaaaaaaaaaaaaaaaa', x'00');\n",
		"trigger":                               "-- kind: expand\nCREATE TRIGGER notes_ai AFTER INSERT ON notes BEGIN SELECT 1; END;\n",
		"view":                                  "-- kind: expand\nCREATE VIEW all_notes AS SELECT id FROM notes;\n",
	} {
		t.Run(name, func(t *testing.T) {
			mt := newMigrationTest(t)
			v2 := mt.binary(binaryAt(t, 2, nil))
			id := createTenant(t, v2)
			addNote(t, acquire(t, v2, id), 1, "body", "kept")
			dir := tenantDir(t, v2, id)
			closeStore(t, v2)
			before := dump(t, dbPath(dir))

			// 0003 commits, then 0004 fails.
			broken := mt.binary(binaryAt(t, 3, map[string]string{"0004_broken": bad}))
			_, _, err := broken.Acquire(ctx, id)
			if !errors.Is(err, ErrMigrationFailed) || !strings.Contains(err.Error(), "restored from") {
				t.Fatalf("error = %v, want ErrMigrationFailed with the file restored", err)
			}
			closeStore(t, broken)
			if after := dump(t, dbPath(dir)); after != before {
				t.Errorf("the file was not restored:\n%s\nwant:\n%s", after, before)
			}
			if names := backups(t, dir); len(names) != 1 {
				t.Errorf("backups %v, want exactly one", names)
			}
			tn := acquire(t, mt.binary(binaryAt(t, 2, nil)), id)
			if got := readNotes(t, tn, "body"); !reflect.DeepEqual(got, map[int64]string{1: "kept"}) {
				t.Errorf("notes after the failed migration: %v", got)
			}
		})
	}
}

func TestForeignKeysAreBackOnAfterAMigration(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	s := mt.binary(binaryAt(t, 2, nil))
	id := createTenant(t, s)
	tn := acquire(t, s, id)
	for _, c := range []struct {
		body string
		ok   bool
	}{
		{"-- kind: expand\nNOT SQL;\n", false},
		{"-- kind: expand\nCREATE TABLE extra (x INTEGER) STRICT;\n", true},
	} {
		st, err := parseMigration(3, "step", []byte(c.body))
		if err != nil {
			t.Fatal(err)
		}
		err = tn.withConn(ctx, func(conn *sql.Conn) error { return s.applyMigration(ctx, conn, id, st, nil) })
		if (err == nil) != c.ok {
			t.Errorf("applying %q: error = %v", c.body, err)
		}
		if !foreignKeysOn(t, tn) {
			t.Errorf("foreign keys are off after applying %q", c.body)
		}
	}
}

// Rollback test 3, N−1 reader: the previous binary opens, reads, and writes a
// file that an expand migration moved beyond it, and changes nothing about
// its version or history.
func TestPreviousBinaryUsesAnExpandedFile(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v2 := mt.binary(binaryAt(t, 2, nil))
	id := createTenant(t, v2)
	addNote(t, acquire(t, v2, id), 1, "body", "from v2")
	dir := tenantDir(t, v2, id)
	closeStore(t, v2)

	v3 := mt.binary(binaryAt(t, 3, nil))
	tn := acquire(t, v3, id)
	addNote(t, tn, 2, "body", "from v3")
	execArgs(t, tn, "UPDATE notes SET tag = ? WHERE id = ?", "tagged", 2)
	closeStore(t, v3)

	prev := mt.binary(binaryAt(t, 2, nil))
	tn = acquire(t, prev, id)
	if ident, history := header(t, tn); ident.schema != 3 || ident.minReader != 1 || len(history) != 3 {
		t.Errorf("previous binary sees schema_version %d, min_reader_version %d, %d migrations; want 3, 1, 3", ident.schema, ident.minReader, len(history))
	}
	if got := readNotes(t, tn, "body"); !reflect.DeepEqual(got, map[int64]string{1: "from v2", 2: "from v3"}) {
		t.Errorf("previous binary reads %v", got)
	}
	addNote(t, tn, 3, "body", "from v2 again")
	closeStore(t, prev)
	if names := backups(t, dir); len(names) != 1 {
		t.Errorf("backups %v, want only the one the upgrade took", names)
	}

	tn = acquire(t, mt.binary(binaryAt(t, 3, nil)), id)
	if got := readNotes(t, tn, "body"); len(got) != 3 {
		t.Errorf("the newer binary reads %v, want all three notes", got)
	}
	var tag string
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx, "SELECT tag FROM notes WHERE id = 2").Scan(&tag)
	})
	if err != nil || tag != "tagged" {
		t.Errorf("the newer binary's column: %q, %v", tag, err)
	}
}

// Rollback test 4, refusal: the previous binary refuses a file that a
// contract migration changed, and writes nothing to it.
func TestPreviousBinaryRefusesAContractedFile(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v3 := mt.binary(binaryAt(t, 3, nil))
	id := createTenant(t, v3)
	addNote(t, acquire(t, v3, id), 1, "body", "note")
	dir := tenantDir(t, v3, id)
	path := dbPath(dir)
	closeStore(t, v3)
	v4 := mt.binary(binaryAt(t, 4, nil))
	acquire(t, v4, id)
	closeStore(t, v4)
	file, names := readFile(t, path), backups(t, dir)

	prev := mt.binary(binaryAt(t, 3, nil))
	_, _, err := prev.Acquire(ctx, id)
	if !errors.Is(err, ErrUnsupportedSchema) || !strings.Contains(err.Error(), "needs schema version 4") {
		t.Fatalf("error = %v, want ErrUnsupportedSchema naming version 4", err)
	}
	closeStore(t, prev)
	if !bytes.Equal(readFile(t, path), file) {
		t.Error("the refused open changed the file")
	}
	if got := backups(t, dir); !slices.Equal(got, names) {
		t.Errorf("backups %v, want %v", got, names)
	}
	acquire(t, mt.binary(binaryAt(t, 4, nil)), id)
}

// Rollback test 5, tamper: a history that does not match the binary's
// migrations is refused before anything is written.
func TestTamperedHistoryIsRefused(t *testing.T) {
	ctx := context.Background()
	zeros := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name           string
		fileAt, binary int64
		edit           string
		binaryExtra    map[string]string
	}{
		{"edited checksum of a shipped migration", 2, 2, "UPDATE schema_migrations SET sha256 = '" + zeros + "' WHERE number = 1", nil},
		{"renamed migration", 2, 2, "UPDATE schema_migrations SET name = 'other' WHERE number = 2", nil},
		{"unknown migration at or below this binary's latest", 2, 3, "UPDATE schema_migrations SET name = 'unknown', sha256 = '" + zeros + "' WHERE number = 2", nil},
		{"missing history row", 3, 3, "DELETE FROM schema_migrations WHERE number = 2", nil},
		{"history with a gap", 3, 3, "UPDATE schema_migrations SET number = 7 WHERE number = 2", nil},
		{"schema version raised without history", 2, 4, "UPDATE tenant SET schema_version = 3", nil},
		{"min_reader_version lowered on a contracted file", 4, 4, "UPDATE tenant SET min_reader_version = 1", nil},
		{"min_reader_version raised on an expanded file", 3, 3, "UPDATE tenant SET min_reader_version = 3", nil},
		{"this binary's copy of a migration was edited", 2, 2, "", map[string]string{"0002_notes": testChain["0002_notes"] + "-- edited\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMigrationTest(t)
			old := mt.binary(binaryAt(t, tc.fileAt, nil))
			id := createTenant(t, old)
			dir := tenantDir(t, old, id)
			path := dbPath(dir)
			closeStore(t, old)
			if tc.edit != "" {
				rawExec(t, path, tc.edit)
			}
			file := readFile(t, path)

			s := mt.binary(binaryAt(t, tc.binary, tc.binaryExtra))
			if _, _, err := s.Acquire(ctx, id); !errors.Is(err, ErrSchemaTampered) {
				t.Fatalf("error = %v, want ErrSchemaTampered", err)
			}
			closeStore(t, s)
			if !bytes.Equal(readFile(t, path), file) {
				t.Error("the refusal wrote to the file")
			}
			if names := backups(t, dir); len(names) != 0 {
				t.Errorf("backups %v, want none", names)
			}
		})
	}
}

// Migrations newer than a binary are expected on an expanded file. The
// binary cannot verify them; the binaries that ship them do.
func TestNewerMigrationsAreVerifiedByTheBinariesThatShipThem(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v3 := mt.binary(binaryAt(t, 3, nil))
	id := createTenant(t, v3)
	path := dbPath(tenantDir(t, v3, id))
	closeStore(t, v3)
	rawExec(t, path, "UPDATE schema_migrations SET sha256 = '"+strings.Repeat("0", 64)+"' WHERE number = 3")

	prev := mt.binary(binaryAt(t, 2, nil))
	acquire(t, prev, id)
	closeStore(t, prev)
	if _, _, err := mt.binary(binaryAt(t, 3, nil)).Acquire(ctx, id); !errors.Is(err, ErrSchemaTampered) {
		t.Errorf("the binary that ships 0003: error = %v, want ErrSchemaTampered", err)
	}
}

func TestMigrationLockIsExclusive(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v2 := mt.binary(binaryAt(t, 2, nil))
	id := createTenant(t, v2)
	dir := tenantDir(t, v2, id)
	path := dbPath(dir)
	closeStore(t, v2)
	file := readFile(t, path)

	// Held as another process would hold it.
	unlock, err := lockForMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockForMigration(dir); !errors.Is(err, ErrInUse) {
		t.Errorf("second lock: error = %v, want ErrInUse", err)
	}
	v3 := mt.binary(binaryAt(t, 3, nil))
	if _, _, err := v3.Acquire(ctx, id); !errors.Is(err, ErrInUse) {
		t.Fatalf("migrating while another holds the lock: error = %v, want ErrInUse", err)
	}
	if !bytes.Equal(readFile(t, path), file) || len(backups(t, dir)) != 0 {
		t.Error("the tenant was backed up or migrated without its lock")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v3.Acquire(ctx, id); err != nil {
		t.Fatalf("after the lock was released: %v", err)
	}
}

func TestMigrationLockMustBeAPlainFile(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v2 := mt.binary(binaryAt(t, 2, nil))
	id := createTenant(t, v2)
	dir := tenantDir(t, v2, id)
	closeStore(t, v2)
	unlock, err := lockForMigration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(lockPath(dir), filepath.Join(dir, "second-name")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mt.binary(binaryAt(t, 3, nil)).Acquire(ctx, id); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("hard-linked lock file: error = %v, want ErrUnsafePath", err)
	}
	if names := backups(t, dir); len(names) != 0 {
		t.Errorf("backups %v, want none", names)
	}
}

func TestRestoreRefusesAnotherTenantsBackup(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v2 := mt.binary(binaryAt(t, 2, nil))
	a, b := createTenant(t, v2), createTenant(t, v2)
	dirA, dirB := tenantDir(t, v2, a), tenantDir(t, v2, b)
	closeStore(t, v2)
	v3 := mt.binary(binaryAt(t, 3, nil))
	acquire(t, v3, a)
	acquire(t, v3, b)
	closeStore(t, v3)
	pathA := dbPath(dirA)
	before := dump(t, pathA)

	// b's backup, planted in a's backups directory under a valid name.
	planted := "pre-migration-v0002-to-v0003-20260913T120000.000000000Z.db"
	p := filepath.Join(backupsPath(dirA), planted)
	if err := createPrivateFile(p); err != nil {
		t.Fatal(err)
	}
	writeInPlace(t, p, readFile(t, filepath.Join(backupsPath(dirB), backups(t, dirB)[0])))

	s := mt.binary(binaryAt(t, 3, nil))
	if err := s.restorePreMigration(ctx, a, planted); !errors.Is(err, ErrForeignFile) {
		t.Errorf("another tenant's backup: error = %v, want ErrForeignFile", err)
	}
	for _, name := range []string{"../" + planted, "store.db", filepath.Join("..", b.String(), backupsDirName, backups(t, dirB)[0])} {
		if err := s.restorePreMigration(ctx, a, name); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("backup name %q: error = %v, want ErrUnsafePath", name, err)
		}
	}
	acquire(t, s, a)
	if err := s.restorePreMigration(ctx, a, backups(t, dirA)[0]); !errors.Is(err, ErrInUse) {
		t.Errorf("restoring a held tenant: error = %v, want ErrInUse", err)
	}
	closeStore(t, s)
	if after := dump(t, pathA); after != before {
		t.Error("a refused restore changed the tenant")
	}
}

func TestDeleteRemovesPreMigrationBackups(t *testing.T) {
	ctx := context.Background()
	mt := newMigrationTest(t)
	v2 := mt.binary(binaryAt(t, 2, nil))
	id := createTenant(t, v2)
	dir := tenantDir(t, v2, id)
	closeStore(t, v2)
	v3 := mt.binary(binaryAt(t, 3, nil))
	_, release, err := v3.Acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if len(backups(t, dir)) != 1 {
		t.Fatal("no pre-migration backup to delete")
	}
	if err := v3.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("tenant directory, with its backups, still present: %v", err)
	}
}
