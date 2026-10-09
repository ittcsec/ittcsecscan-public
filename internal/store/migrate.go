package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sqlite "modernc.org/sqlite"
)

// Migrations ship inside the binary and are never edited once released
// (ADR-0011 §2). Each file is NNNN_name.sql, and its first line declares its
// kind: "-- kind: base", "-- kind: expand", or "-- kind: contract".
//
//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// productionMigrations loads and validates the embedded migrations once. New
// refuses to run with an invalid set.
var productionMigrations = sync.OnceValues(func() (*migrationSet, error) {
	return loadMigrations(embeddedMigrations, "migrations")
})

// migrationKind says what a migration means for older binaries (ADR-0011 §2).
type migrationKind int

const (
	// kindBase is migration 0001 only: the file's identity and history.
	kindBase migrationKind = iota + 1
	// kindExpand is additive: the previous binary can still use the file.
	kindExpand
	// kindContract is breaking: it raises min_reader_version to its own
	// number, so every older binary refuses the file.
	kindContract
)

var migrationKinds = map[string]migrationKind{"base": kindBase, "expand": kindExpand, "contract": kindContract}

// tenantIDPlaceholder is replaced by the file's tenant ID when a migration is
// applied, for per-file constraints such as CHECK (tenant_id = '...'). The
// checksum covers the template, so it is the same for every tenant.
const tenantIDPlaceholder = "{{tenant_id}}"

var (
	migrationFileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)
	backupFileName    = regexp.MustCompile(`^pre-migration-v[0-9]{4,}-to-v[0-9]{4,}-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z\.db$`)
)

// migration is one numbered schema step.
type migration struct {
	number   int64
	name     string
	kind     migrationKind
	template string
	checksum string // hex SHA-256 of the file as shipped
}

func (m migration) String() string { return fmt.Sprintf("%04d_%s", m.number, m.name) }

// render fills in the tenant ID. A TenantID is 26 base32 characters, so it
// cannot break out of the quoted literal it replaces.
func (m migration) render(id TenantID) string {
	return strings.ReplaceAll(m.template, tenantIDPlaceholder, id.String())
}

// migrationSet is one binary's migrations, numbered 1 to latest without gaps.
type migrationSet struct {
	steps []migration
}

// loadMigrations reads and validates every migration in dir.
func loadMigrations(fsys fs.FS, dir string) (*migrationSet, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("store: reading migrations: %w", err)
	}
	steps := make([]migration, 0, len(entries))
	for _, e := range entries {
		m := migrationFileName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			return nil, fmt.Errorf("store: %q is not a migration file (want NNNN_name.sql)", e.Name())
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: reading migration %s: %w", e.Name(), err)
		}
		st, err := parseMigration(n, m[2], b)
		if err != nil {
			return nil, err
		}
		steps = append(steps, st)
	}
	return newMigrationSet(steps)
}

func parseMigration(number int64, name string, b []byte) (migration, error) {
	id := fmt.Sprintf("%04d_%s", number, name)
	text := string(b)
	if !utf8.ValidString(text) {
		return migration{}, fmt.Errorf("store: migration %s is not valid UTF-8", id)
	}
	// A checkout that converted line endings would change the checksum.
	if strings.ContainsRune(text, '\r') {
		return migration{}, fmt.Errorf("store: migration %s must use LF line endings", id)
	}
	first, body, _ := strings.Cut(text, "\n")
	kindName, ok := strings.CutPrefix(first, "-- kind: ")
	kind := migrationKinds[kindName]
	if !ok || kind == 0 {
		return migration{}, fmt.Errorf("store: migration %s must start with a line \"-- kind: base\", \"-- kind: expand\", or \"-- kind: contract\"", id)
	}
	if rest := strings.ReplaceAll(body, tenantIDPlaceholder, ""); strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
		return migration{}, fmt.Errorf("store: migration %s has a placeholder other than %s", id, tenantIDPlaceholder)
	}
	if strings.TrimSpace(body) == "" {
		return migration{}, fmt.Errorf("store: migration %s is empty", id)
	}
	sum := sha256.Sum256(b)
	return migration{number: number, name: name, kind: kind, template: text, checksum: hex.EncodeToString(sum[:])}, nil
}

func newMigrationSet(steps []migration) (*migrationSet, error) {
	if len(steps) == 0 {
		return nil, errors.New("store: no migrations")
	}
	for i, st := range steps {
		if st.number != int64(i+1) {
			return nil, fmt.Errorf("store: migrations must be numbered 0001, 0002, ... without gaps or repeats; found %s in position %d", st, i+1)
		}
		if (st.number == 1) != (st.kind == kindBase) {
			return nil, fmt.Errorf("store: migration %s: 0001, and only 0001, is the base migration", st)
		}
	}
	return &migrationSet{steps: steps}, nil
}

// latest is the schema version this binary writes.
func (ms *migrationSet) latest() int64 { return int64(len(ms.steps)) }

// minReaderAt is the min_reader_version of a file at schema version v, for
// 1 ≤ v ≤ latest: the number of the last contract migration up to v, or 1.
func (ms *migrationSet) minReaderAt(v int64) int64 {
	r := int64(1)
	for _, st := range ms.steps[:v] {
		if st.kind == kindContract {
			r = st.number
		}
	}
	return r
}

// recordedMigration is one row of a file's schema_migrations table.
type recordedMigration struct {
	number   int64
	name     string
	checksum string
}

// openAction is what the open-time rules decide for a file.
type openAction int

const (
	// openAsIs: the file is at this binary's version, or was only expanded
	// beyond it.
	openAsIs openAction = iota + 1
	// migrateForward: the file is older than this binary.
	migrateForward
)

// decide applies ADR-0011 §2's open-time rules to a file's versions and
// migration history. It never writes, so a refusal leaves the file as it was.
func (ms *migrationSet) decide(ident identity, history []recordedMigration) (openAction, error) {
	v, r, latest := ident.schema, ident.minReader, ms.latest()
	if v < 1 || r < 1 || r > v {
		return 0, fmt.Errorf("%w: schema version %d with min_reader_version %d", ErrSchemaTampered, v, r)
	}
	if int64(len(history)) != v {
		return 0, fmt.Errorf("%w: %d migrations recorded for schema version %d", ErrSchemaTampered, len(history), v)
	}
	for i, h := range history {
		if h.number != int64(i+1) {
			return 0, fmt.Errorf("%w: the migration history skips from %d to %d", ErrSchemaTampered, i, h.number)
		}
		// Migrations newer than this binary are expected on an expanded
		// file. The binaries that ship them verify their checksums.
		if h.number > latest {
			continue
		}
		if st := ms.steps[h.number-1]; h.name != st.name || h.checksum != st.checksum {
			return 0, fmt.Errorf("%w: recorded migration %04d is not the %s this binary ships", ErrSchemaTampered, h.number, st)
		}
	}
	if r > latest {
		return 0, fmt.Errorf("%w: this tenant was upgraded by a newer ittcsecscan; it needs schema version %d or later, and this binary supports up to %d", ErrUnsupportedSchema, r, latest)
	}
	if v <= latest && r != ms.minReaderAt(v) {
		return 0, fmt.Errorf("%w: min_reader_version is %d, but the recorded migrations give %d", ErrSchemaTampered, r, ms.minReaderAt(v))
	}
	if v < latest {
		return migrateForward, nil
	}
	return openAsIs, nil
}

// readHeader reads a file's identity row and migration history.
func readHeader(ctx context.Context, c *sql.Conn) (identity, []recordedMigration, error) {
	ident, err := readIdentity(ctx, c)
	if err != nil {
		return identity{}, nil, err
	}
	rows, err := c.QueryContext(ctx, "SELECT number, name, sha256 FROM schema_migrations ORDER BY number")
	if err != nil {
		return identity{}, nil, fmt.Errorf("%w: reading the migration history: %w", ErrForeignFile, err)
	}
	var history []recordedMigration
	for rows.Next() {
		var h recordedMigration
		if err := rows.Scan(&h.number, &h.name, &h.checksum); err != nil {
			return identity{}, nil, errors.Join(fmt.Errorf("%w: reading the migration history: %w", ErrForeignFile, err), rows.Close())
		}
		history = append(history, h)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return identity{}, nil, fmt.Errorf("%w: reading the migration history: %w", ErrForeignFile, err)
	}
	return ident, history, nil
}

// sameTenantKeys reports whether two readings of a file's identity name the
// same tenant with the same wrapped keys.
func sameTenantKeys(a, b identity) bool {
	return a.tenantID == b.tenantID && a.generation == b.generation &&
		bytes.Equal(a.wrappedData, b.wrappedData) && bytes.Equal(a.wrappedID, b.wrappedID)
}

// baseIdentity is the identity row written together with migration 0001.
type baseIdentity struct {
	generation  uint32
	wrappedData []byte
	wrappedID   []byte
	createdAt   time.Time
}

// initSchema builds a new tenant file: migration 0001 together with the
// identity row, then every later migration, then statistics.
func (s *Store) initSchema(ctx context.Context, c *sql.Conn, id TenantID, base baseIdentity) error {
	for i, st := range s.migrations.steps {
		b := &base
		if i > 0 {
			b = nil
		}
		if err := s.applyMigration(ctx, c, id, st, b); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrMigrationFailed, st, err)
		}
	}
	if _, err := c.ExecContext(ctx, "ANALYZE"); err != nil {
		return fmt.Errorf("store: refreshing statistics: %w", err)
	}
	return nil
}

// migrate brings an open tenant's file up to this binary's schema version
// (ADR-0011 §2). It holds the tenant's migration lock, backs the file up,
// applies each migration in its own transaction, and restores the backup if
// any step fails, so the file ends either fully migrated or as it was. It
// runs before the handle is handed out, after the tenant's keys unwrapped.
func (s *Store) migrate(ctx context.Context, t *Tenant, dir string, opened identity) (err error) {
	unlock, err := lockForMigration(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return t.withConn(ctx, func(c *sql.Conn) error {
		// Another process may have migrated the file before the lock was taken.
		cur, history, err := readHeader(ctx, c)
		if err != nil {
			return err
		}
		if !sameTenantKeys(cur, opened) {
			return fmt.Errorf("%w: the file's identity changed while it was being opened", ErrForeignFile)
		}
		action, err := s.migrations.decide(cur, history)
		if err != nil || action == openAsIs {
			return err
		}
		backup, err := s.backupTenant(ctx, c, t.id, dir, cur.schema)
		if err != nil {
			return err
		}
		for _, st := range s.migrations.steps[cur.schema:] {
			if err := s.applyMigration(ctx, c, t.id, st, nil); err != nil {
				failed := fmt.Errorf("%w: %s: %w", ErrMigrationFailed, st, err)
				// The restore runs even if ctx was cancelled mid-migration.
				if rerr := restoreBackup(context.WithoutCancel(ctx), c, dbPath(dir), backup, t.id, cur.schema); rerr != nil {
					return errors.Join(failed, fmt.Errorf("store: restoring %s also failed, so the file stays at the last migration that completed: %w", filepath.Base(backup), rerr))
				}
				return fmt.Errorf("%w; the file was restored from %s", failed, filepath.Base(backup))
			}
		}
		if _, err := c.ExecContext(ctx, "ANALYZE"); err != nil {
			return fmt.Errorf("store: refreshing statistics after migration: %w", err)
		}
		after, history, err := readHeader(ctx, c)
		if err != nil {
			return err
		}
		if after.schema != s.migrations.latest() || !sameTenantKeys(after, cur) {
			return fmt.Errorf("%w: after migrating, the file is at schema version %d with a changed identity", ErrMigrationFailed, after.schema)
		}
		_, err = s.migrations.decide(after, history)
		return err
	})
}

// applyMigration applies one migration in its own transaction. Foreign keys
// are off while it runs, as SQLite requires for table rebuilds, and are
// checked with foreign_key_check before commit; they are switched back on,
// and verified, whatever happens. base is the identity row to write with
// migration 0001, and nil for every other migration.
func (s *Store) applyMigration(ctx context.Context, c *sql.Conn, id TenantID, st migration, base *baseIdentity) (err error) {
	if (base != nil) != (st.kind == kindBase) {
		return errors.New("the base migration, and only it, is applied with the identity row")
	}
	if _, err := c.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("%w: PRAGMA foreign_keys = OFF: %w", ErrHardening, err)
	}
	defer func() { err = errors.Join(err, enableForeignKeys(context.WithoutCancel(ctx), c)) }()
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := s.migrationBody(ctx, tx, id, st, base); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

func (s *Store) migrationBody(ctx context.Context, tx *sql.Tx, id TenantID, st migration, base *baseIdentity) error {
	minReader := int64(1)
	if base == nil {
		var v int64
		if err := tx.QueryRowContext(ctx, "SELECT schema_version, min_reader_version FROM tenant WHERE singleton = 1").Scan(&v, &minReader); err != nil {
			return fmt.Errorf("reading the schema version: %w", err)
		}
		if v != st.number-1 {
			return fmt.Errorf("the file is at schema version %d, not %d", v, st.number-1)
		}
	}
	if _, err := tx.ExecContext(ctx, st.render(id)); err != nil {
		return err
	}
	if st.kind == kindContract {
		minReader = st.number
	}
	if base != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tenant (singleton, tenant_id, created_at, schema_version, min_reader_version, key_generation, wrapped_data_key, wrapped_id_key)
			 VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
			id.String(), base.createdAt.UTC().Format(time.RFC3339Nano), st.number, minReader,
			base.generation, base.wrappedData, base.wrappedID); err != nil {
			return fmt.Errorf("writing the identity row: %w", err)
		}
	} else {
		res, err := tx.ExecContext(ctx, "UPDATE tenant SET schema_version = ?, min_reader_version = ? WHERE singleton = 1", st.number, minReader)
		if err != nil {
			return fmt.Errorf("recording the schema version: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("recording the schema version: %d identity rows updated (%w)", n, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (number, tenant_id, name, sha256, applied_by, applied_at) VALUES (?, ?, ?, ?, ?, ?)",
		st.number, id.String(), st.name, st.checksum, s.binaryVersion, s.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("recording the migration: %w", err)
	}
	return checkMigrated(ctx, tx)
}

// checkMigrated runs the checks a migration must pass before it commits.
func checkMigrated(ctx context.Context, tx *sql.Tx) error {
	var code int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger', 'view')").Scan(&code); err != nil {
		return err
	}
	if code != 0 {
		return errors.New("a migration may not create triggers or views, which could run code when the file is read")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	violation := rows.Next()
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if violation {
		return errors.New("foreign_key_check found rows that violate a foreign key")
	}
	return quickCheck(ctx, tx)
}

// quickCheck runs PRAGMA quick_check, which returns the single row "ok" for
// an intact database.
func quickCheck(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var res string
	if err := q.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("quick_check: %q", res)
	}
	return nil
}

func enableForeignKeys(ctx context.Context, c *sql.Conn) error {
	if _, err := c.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("%w: PRAGMA foreign_keys = ON after a migration: %w", ErrHardening, err)
	}
	var on int64
	if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&on); err != nil {
		return fmt.Errorf("%w: reading PRAGMA foreign_keys after a migration: %w", ErrHardening, err)
	}
	if on != 1 {
		return fmt.Errorf("%w: PRAGMA foreign_keys = %d after a migration, want 1", ErrHardening, on)
	}
	return nil
}

// backupTenant writes an online backup of the tenant's file to
// <tenant>/backups before a migration, then verifies it. The copy is taken
// through SQLite's backup API, so it is consistent even while other
// connections use the file. It sits in the tenant's own directory, with the
// same owner-only protection as the file, and is deleted with the tenant.
func (s *Store) backupTenant(ctx context.Context, c *sql.Conn, id TenantID, dir string, version int64) (string, error) {
	bdir := backupsPath(dir)
	if err := ensurePrivateDir(bdir); err != nil {
		return "", err
	}
	name := fmt.Sprintf("pre-migration-v%04d-to-v%04d-%s.db", version, s.migrations.latest(), s.now().UTC().Format("20060102T150405.000000000Z"))
	p := filepath.Join(bdir, name)
	if err := createPrivateFile(p); err != nil {
		return "", fmt.Errorf("store: creating the pre-migration backup: %w", err)
	}
	if err := onlineCopy(c, p); err != nil {
		// Only the incomplete copy this call just created is removed.
		return "", errors.Join(fmt.Errorf("store: writing the pre-migration backup %s: %w", name, err), os.Remove(p))
	}
	db, bc, err := openBackup(ctx, p)
	if err != nil {
		return "", err
	}
	_, err = checkBackup(ctx, bc, id, version)
	if err := errors.Join(err, bc.Close(), db.Close()); err != nil {
		return "", fmt.Errorf("store: verifying the pre-migration backup %s: %w", name, err)
	}
	return p, nil
}

// openBackup opens a backup file, after the same path checks as a tenant
// file, on a hardened connection.
func openBackup(ctx context.Context, p string) (*sql.DB, *sql.Conn, error) {
	if _, err := plainFile(p); err != nil {
		return nil, nil, err
	}
	if err := errors.Join(private(p), checkSidecarsPlain(p)); err != nil {
		return nil, nil, err
	}
	return openDB(ctx, p)
}

// checkBackup checks that an open backup is this tenant's, intact, and at the
// schema version wanted (any version when want is 0), and returns its
// identity.
func checkBackup(ctx context.Context, c *sql.Conn, id TenantID, want int64) (identity, error) {
	ident, err := readIdentity(ctx, c)
	if err != nil {
		return identity{}, err
	}
	if ident.tenantID != id.String() {
		return identity{}, fmt.Errorf("%w: the backup belongs to a different tenant", ErrForeignFile)
	}
	if want != 0 && ident.schema != want {
		return identity{}, fmt.Errorf("%w: the backup is at schema version %d, want %d", ErrForeignFile, ident.schema, want)
	}
	if err := quickCheck(ctx, c); err != nil {
		return identity{}, fmt.Errorf("store: the backup is damaged: %w", err)
	}
	return ident, nil
}

// restoreBackup copies a backup back over the tenant's live file. The backup
// is opened and verified first, and the copy is taken from that same open
// connection, so the file verified is the file copied. The copy goes through
// SQLite's backup API under SQLite's own locking, so the live file is never
// left half-written. want is the schema version the backup must be at, or 0
// for any.
func restoreBackup(ctx context.Context, live *sql.Conn, livePath, backup string, id TenantID, want int64) (err error) {
	db, bc, err := openBackup(ctx, backup)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, bc.Close(), db.Close()) }()
	ident, err := checkBackup(ctx, bc, id, want)
	if err != nil {
		return err
	}
	if err := onlineCopy(bc, livePath); err != nil {
		return fmt.Errorf("store: restoring from %s: %w", filepath.Base(backup), err)
	}
	got, err := readIdentity(ctx, live)
	if err != nil {
		return err
	}
	if !sameTenantKeys(got, ident) || got.schema != ident.schema {
		return fmt.Errorf("%w: after the restore the live file is at schema version %d, want %d", ErrForeignFile, got.schema, ident.schema)
	}
	return nil
}

// onlineCopy copies the whole database behind src into the database file dst
// through SQLite's online backup API.
func onlineCopy(src *sql.Conn, dst string) error {
	return src.Raw(func(dc any) error {
		d, ok := dc.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("the SQLite driver does not support online backup")
		}
		b, err := d.NewBackup(dst)
		if err != nil {
			return err
		}
		more, err := b.Step(-1)
		if err == nil && more {
			err = errors.New("the online copy stopped before the last page")
		}
		return errors.Join(err, b.Finish())
	})
}

// restorePreMigration replaces tenant id's file with one of its pre-migration
// backups, named as in its backups directory. Rolling back a contract
// migration means exactly this (ADR-0011 §2); scans made after the migration
// are lost. It works whatever the live file's schema version, so an older
// binary can roll back a file a newer one migrated. The tenant must not be
// held.
func (s *Store) restorePreMigration(ctx context.Context, id TenantID, backupName string) (err error) {
	if !backupFileName.MatchString(backupName) {
		return fmt.Errorf("%w: %q is not a pre-migration backup name", ErrUnsafePath, backupName)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if e := s.open[id]; e != nil {
		if e.refs > 0 {
			return ErrInUse
		}
		if err := s.evictLocked(e); err != nil {
			return err
		}
	}
	f, err := s.checkTenantFiles(id)
	if err != nil {
		return err
	}
	unlock, err := lockForMigration(f.dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	db, c, err := openDB(ctx, f.db)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.Close(), db.Close()) }()
	cur, err := readIdentity(ctx, c)
	if err != nil {
		return err
	}
	if cur.tenantID != id.String() {
		return fmt.Errorf("%w: the file identifies a different tenant", ErrForeignFile)
	}
	return restoreBackup(ctx, c, f.db, filepath.Join(backupsPath(f.dir), backupName), id, 0)
}
