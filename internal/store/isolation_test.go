package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The tenant-isolation properties of ADR-0010 §3. Properties 1 and 5 (key
// level) are in tenantid_test.go and keys_test.go; property 3 is in the
// redirect tests.

// Property 2: no path input anywhere.
func TestNoPathSelectsATenant(t *testing.T) {
	ctxType := reflect.TypeFor[context.Context]()
	idType := reflect.TypeFor[TenantID]()
	st := reflect.TypeFor[*Store]()
	for i := range st.NumMethod() {
		m := st.Method(i)
		for j := 1; j < m.Type.NumIn(); j++ {
			if in := m.Type.In(j); in != ctxType && in != idType {
				t.Errorf("Store.%s takes a %v: a tenant is selected only by TenantID", m.Name, in)
			}
		}
	}
	it := reflect.TypeFor[TenantID]()
	for i := range it.NumField() {
		if it.Field(i).IsExported() {
			t.Errorf("TenantID.%s is exported: a TenantID must come only from NewTenantID or ParseTenantID", it.Field(i).Name)
		}
	}
	// The configuration cannot name a tenant database. data_dir is the store's
	// root, under which tenants are found only by ID; master_key_file names the
	// master-key file, which is validated to lie outside data_dir (ADR-0015) and
	// so can never point at a tenant database. No other key is a path.
	if got, want := configKeys(t), []string{"data_dir", "log", "log.format", "log.level", "master_key_file", "schema_version"}; !slices.Equal(got, want) {
		t.Errorf("configuration keys are %v, want %v. Check that no new key can select a tenant database, then update this list.", got, want)
	}
}

func configKeys(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "config", "v1", "config.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var keys []string
	var walk func(prefix string, node map[string]any)
	walk = func(prefix string, node map[string]any) {
		props, _ := node["properties"].(map[string]any)
		for name, sub := range props {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			keys = append(keys, full)
			if m, ok := sub.(map[string]any); ok {
				walk(full, m)
			}
		}
	}
	walk("", root)
	slices.Sort(keys)
	return keys
}

// Property 4: swapped or planted files are refused.
func TestSwappedOrPlantedFilesAreRefused(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		plant func(t *testing.T, dbA, dbB string, a, b TenantID)
	}{
		{"another tenant's database copied over", func(t *testing.T, dbA, dbB string, _, _ TenantID) {
			writeInPlace(t, dbA, readFile(t, dbB))
		}},
		{"identity rewritten to another tenant", func(t *testing.T, dbA, _ string, _, b TenantID) {
			// The file's own CHECK refuses another tenant's ID; an attacker
			// with file access can switch CHECK constraints off.
			rawExec(t, dbA, "PRAGMA ignore_check_constraints = ON; UPDATE tenant SET tenant_id = '"+b.String()+"'")
		}},
		{"identity row removed", func(t *testing.T, dbA, _ string, _, _ TenantID) {
			rawExec(t, dbA, "DELETE FROM tenant")
		}},
		{"trigger planted", func(t *testing.T, dbA, _ string, _, _ TenantID) {
			rawExec(t, dbA, "CREATE TABLE t (x INTEGER)", "CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT 1; END")
		}},
		{"view planted", func(t *testing.T, dbA, _ string, _, _ TenantID) {
			rawExec(t, dbA, "CREATE VIEW v AS SELECT 1")
		}},
		{"not a database", func(t *testing.T, dbA, _ string, _, _ TenantID) {
			writeInPlace(t, dbA, []byte("this is not a SQLite database, just planted bytes"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			a, b := createTenant(t, s), createTenant(t, s)
			dbA, dbB := dbPath(tenantDir(t, s, a)), dbPath(tenantDir(t, s, b))
			tc.plant(t, dbA, dbB, a, b)
			_, _, err := s.Acquire(ctx, a)
			if !errors.Is(err, ErrForeignFile) && !errors.Is(err, ErrHardening) {
				t.Fatalf("Acquire after %s: error = %v, want a refusal", tc.name, err)
			}
			acquire(t, s, b) // the other tenant is unaffected
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads a file it created
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeInPlace replaces a file's content, keeping its name and permissions.
func writeInPlace(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Property 5, store level: wrong keys are refused, and sealed values are
// bound to their tenant, field, and row (ADR-0013).
func TestWrongMasterKeyOrGenerationIsRefused(t *testing.T) {
	ctx := context.Background()
	s, o := newTestStore(t)
	a := createTenant(t, s)

	wrongKey := openStore(t, Options{DataDir: o.DataDir, Keys: staticKeys(t, testMasterKey(t, 1))})
	if _, _, err := wrongKey.Acquire(ctx, a); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("another master key: error = %v, want ErrKeyMismatch", err)
	}
	wrongGen := openStore(t, Options{DataDir: o.DataDir, Keys: staticKeys(t, testMasterKey(t, 2))})
	if _, _, err := wrongGen.Acquire(ctx, a); !errors.Is(err, ErrKeyMismatch) || !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("missing generation: error = %v, want ErrKeyMismatch and ErrNoMasterKey", err)
	}
	acquire(t, s, a) // the right key still opens it
}

func TestSealedValuesAreBound(t *testing.T) {
	s, ids, _ := fixtureStore(t)
	ta, tb := acquire(t, s, ids[0]), acquire(t, s, ids[1])
	rows := readFixture(t, ta)
	r1, r2 := rows[0], rows[1]
	name, err := ta.OpenValue(FieldEntityName(), r1.node, r1.nameSealed)
	if err != nil || !slices.Contains(sharedNames, string(name)) {
		t.Fatalf("the right tenant, field, and row must decrypt: %q, %v", name, err)
	}
	for what, try := range map[string]func() ([]byte, error){
		"another row":                  func() ([]byte, error) { return ta.OpenValue(FieldEntityName(), r2.node, r1.nameSealed) },
		"another field":                func() ([]byte, error) { return ta.OpenValue(FieldEntityNativeID(), r1.node, r1.nameSealed) },
		"another table's field":        func() ([]byte, error) { return ta.OpenValue(FieldClassificationLabel(), r1.node, r1.nameSealed) },
		"another tenant, same node ID": func() ([]byte, error) { return tb.OpenValue(FieldEntityName(), r1.node, r1.nameSealed) },
	} {
		if _, err := try(); !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("value moved to %s: error = %v, want ErrKeyMismatch", what, err)
		}
	}
}

func TestMasterKeyIsNeverPersisted(t *testing.T) {
	ctx := context.Background()
	key := testMasterKey(t, 1)
	s, ids, o := fixtureStore(t, func(o *Options) { o.Keys = staticKeys(t, key) })
	for _, id := range ids {
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		_ = readFixture(t, tn)
		release()
	}
	if err := s.Delete(ctx, ids[2]); err != nil {
		t.Fatal(err)
	}
	raw := key.key[:]
	needles := [][]byte{
		raw,
		[]byte(hex.EncodeToString(raw)),
		bytes.ToUpper([]byte(hex.EncodeToString(raw))),
		[]byte(base64.StdEncoding.EncodeToString(raw)),
		[]byte(base64.RawStdEncoding.EncodeToString(raw)),
		[]byte(base64.URLEncoding.EncodeToString(raw)),
		[]byte(base64.RawURLEncoding.EncodeToString(raw)),
	}
	files := 0
	err := filepath.WalkDir(o.DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		content := readFile(t, p)
		for _, n := range needles {
			if bytes.Contains(content, n) {
				t.Errorf("%s contains the master key", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 2 {
		t.Fatalf("scanned only %d files: the test did not exercise the store", files)
	}
}

// Property 6: SQL cannot reach another file.
func TestSQLCannotReachAnotherFile(t *testing.T) {
	ctx := context.Background()
	// With room for one open tenant, each Acquire below evicts and reopens,
	// so every new connection is checked.
	s, _ := newTestStore(t, func(o *Options) { o.MaxOpen = 1 })
	a, b := createTenant(t, s), createTenant(t, s)
	check := func(id, other TenantID) {
		t.Helper()
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		err = tn.withConn(ctx, func(c *sql.Conn) error {
			for _, target := range []string{dbPath(tenantDir(t, s, other)), ":memory:", ""} {
				if _, err := c.ExecContext(ctx, "ATTACH DATABASE ? AS other", target); err == nil {
					return fmt.Errorf("ATTACH %q succeeded", target)
				}
			}
			return assertHardened(ctx, c)
		})
		if err != nil {
			t.Errorf("tenant %s: %v", id, err)
		}
		if st := tn.db.Stats(); st.MaxOpenConnections != 1 || st.OpenConnections != 1 {
			t.Errorf("tenant %s has %d connections (max %d), want exactly one", id, st.OpenConnections, st.MaxOpenConnections)
		}
	}
	check(a, b)
	check(b, a)
	check(a, b)
}

// assertHardened reads the connection's safety settings without changing them.
func assertHardened(ctx context.Context, c *sql.Conn) error {
	if n, err := sqlite.Limit(c, sqlite3.SQLITE_LIMIT_ATTACHED, -1); err != nil || n != 0 {
		return fmt.Errorf("attached-database limit = %d (%w)", n, err)
	}
	for q, want := range map[string]string{
		"PRAGMA trusted_schema":  "0",
		"PRAGMA temp_store":      "2",
		"PRAGMA foreign_keys":    "1",
		"PRAGMA secure_delete":   "1",
		"PRAGMA journal_mode":    "wal",
		"PRAGMA writable_schema": "0",
	} {
		var got string
		if err := c.QueryRowContext(ctx, q).Scan(&got); err != nil || got != want {
			return fmt.Errorf("%s = %q, want %q (%w)", q, got, want, err)
		}
	}
	// Defensive mode: writable_schema cannot be switched on.
	if _, err := c.ExecContext(ctx, "PRAGMA writable_schema = ON"); err != nil {
		return err
	}
	var ws string
	if err := c.QueryRowContext(ctx, "PRAGMA writable_schema").Scan(&ws); err != nil || ws != "0" {
		return fmt.Errorf("defensive mode is off: writable_schema = %q (%w)", ws, err)
	}
	return nil
}

// Property 7: handles stay separate under concurrency, including eviction.
func TestHandlesStaySeparateUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, func(o *Options) { o.MaxOpen = 2 })
	ids := []TenantID{createTenant(t, s), createTenant(t, s), createTenant(t, s)}
	for _, id := range ids {
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		exec(t, tn, "CREATE TABLE markers (tenant_id TEXT NOT NULL, writer INTEGER NOT NULL) STRICT")
		release()
	}
	const workers, rounds = 24, 25
	want := make([]int, len(ids))
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := range workers {
		for r := range rounds {
			want[(w+r)%len(ids)]++
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				id := ids[(w+r)%len(ids)]
				tn, release, err := s.Acquire(ctx, id)
				if err != nil {
					errs <- err
					return
				}
				if tn.ID() != id {
					errs <- fmt.Errorf("asked for %s, got a handle for %s", id, tn.ID())
				}
				if n := s.openCount(); n > 2 {
					errs <- fmt.Errorf("%d tenants open, cap is 2", n)
				}
				err = tn.withConn(ctx, func(c *sql.Conn) error {
					_, err := c.ExecContext(ctx, "INSERT INTO markers (tenant_id, writer) VALUES (?, ?)", id.String(), w)
					return err
				})
				release()
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// Release each tenant before the next: the pool holds only two.
	for i, id := range ids {
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		err = tn.withConn(ctx, func(c *sql.Conn) error {
			rows, err := c.QueryContext(ctx, "SELECT tenant_id, count(*) FROM markers GROUP BY tenant_id")
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			groups := 0
			for rows.Next() {
				var tid string
				var n int
				if err := rows.Scan(&tid, &n); err != nil {
					return err
				}
				groups++
				if tid != id.String() || n != want[i] {
					return fmt.Errorf("file of %s holds %d markers of %s, want %d of its own", id, n, tid, want[i])
				}
			}
			if groups != 1 {
				return fmt.Errorf("file of %s holds markers of %d tenants", id, groups)
			}
			return rows.Err()
		})
		release()
		if err != nil {
			t.Error(err)
		}
	}
}

func (s *Store) openCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.open)
}

// Property 8: stable IDs and sealed values do not correlate across tenants.
func TestStableIDsDoNotCorrelateAcrossTenants(t *testing.T) {
	s, ids, _ := fixtureStore(t)
	sets := make([]map[string]bool, len(ids))
	seenSealed := map[string]int{}
	for i, id := range ids {
		tn := acquire(t, s, id)
		rows := readFixture(t, tn)
		if len(rows) != fixtureSizes[i] {
			t.Fatalf("tenant %d holds %d rows, want %d", i, len(rows), fixtureSizes[i])
		}
		sets[i] = map[string]bool{}
		for _, r := range rows {
			sets[i][r.stableID] = true
			for _, blob := range [][]byte{r.nativeSealed, r.nameSealed} {
				if j, dup := seenSealed[string(blob)]; dup && j != i {
					t.Errorf("tenants %d and %d share a sealed value", j, i)
				}
				seenSealed[string(blob)] = i
			}
		}
	}
	for i := range sets {
		for j := i + 1; j < len(sets); j++ {
			for sid := range sets[i] {
				if sets[j][sid] {
					t.Errorf("tenants %d and %d share stable ID %s", i, j, sid)
				}
			}
		}
	}
	// Within one tenant the ID is stable, and it is the one stored.
	tn := acquire(t, s, ids[0])
	x, _ := tn.StableID(sharedNativeIDs[0])
	y, _ := tn.StableID(sharedNativeIDs[0])
	if x != y || !sets[0][x] {
		t.Error("a tenant's stable ID for one native identifier must not change")
	}
}

// Property 9: deletion is immediate and complete in the running system.
// Tenant aliases are not implemented yet, so no alias can refer to a tenant.
func TestDeletionIsImmediateAndComplete(t *testing.T) {
	ctx := context.Background()
	s, ids, _ := fixtureStore(t)
	a := ids[0]
	dirA := tenantDir(t, s, a)

	held, release, err := s.Acquire(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, a); !errors.Is(err, ErrInUse) {
		t.Fatalf("deleting a held tenant: error = %v, want ErrInUse", err)
	}
	release()
	if err := s.Delete(ctx, a); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := os.Lstat(dirA); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("tenant directory still present: %v", err)
	}
	if _, _, err := s.Acquire(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Errorf("Acquire after Delete: error = %v, want ErrNotFound", err)
	}
	s.mu.Lock()
	_, pooled := s.open[a]
	s.mu.Unlock()
	if pooled {
		t.Error("the pool still holds the deleted tenant")
	}
	if _, err := held.SealValue(FieldEntityName(), 1, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("the old handle still works: %v", err)
	}
	if _, err := held.StableID("x"); !errors.Is(err, ErrClosed) {
		t.Errorf("the old handle's keys survive: %v", err)
	}
	entries, err := os.ReadDir(s.layout.tenantsRoot)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, other := range ids[1:] {
		if !slices.Contains(names, other.String()) {
			t.Errorf("tenant %s disappeared", other)
		}
		if n := len(readFixture(t, acquire(t, s, other))); n == 0 {
			t.Errorf("tenant %s lost its data", other)
		}
	}
	if len(names) != len(ids)-1 {
		t.Errorf("tenants root holds %v, want only the two remaining tenants", names)
	}
	if err := s.Delete(ctx, a); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: error = %v, want ErrNotFound", err)
	}
}

// Property 10: the edges behave.
func TestEmptyTenantWorks(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	if _, err := tn.StableID("anything"); err != nil {
		t.Fatal(err)
	}
	sealed, err := tn.SealValue(FieldEntityName(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := tn.OpenValue(FieldEntityName(), 1, sealed); err != nil || len(pt) != 0 {
		t.Fatalf("empty value round trip: %q, %v", pt, err)
	}
}

func TestCreateTakesNoNameAndIDsAreUnique(t *testing.T) {
	m, ok := reflect.TypeFor[*Store]().MethodByName("Create")
	if !ok || m.Type.NumIn() != 2 {
		t.Fatal("Create must take only a context: tenant IDs are never derived from input")
	}
	s, _ := newTestStore(t)
	seen := map[TenantID]bool{}
	for range 10 {
		id := createTenant(t, s)
		if seen[id] {
			t.Fatalf("duplicate tenant ID %s", id)
		}
		seen[id] = true
	}
}

type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

func TestIDCollisionNeverOverwrites(t *testing.T) {
	s, _ := newTestStore(t, func(o *Options) { o.Rand = constReader(0x42) })
	id := createTenant(t, s)
	if _, err := s.Create(context.Background()); err == nil {
		t.Fatal("a second tenant with the same ID was created")
	}
	acquire(t, s, id) // the first tenant is intact
}

func TestEveryRowBelongsToItsFile(t *testing.T) {
	s, ids, _ := fixtureStore(t)
	for _, id := range ids {
		for _, r := range readFixture(t, acquire(t, s, id)) {
			if r.tenantID != id.String() {
				t.Fatalf("file of %s holds a row of %s", id, r.tenantID)
			}
		}
	}
}

func TestCreatedFilesAreOwnerOnly(t *testing.T) {
	s, _ := newTestStore(t)
	dir := tenantDir(t, s, createTenant(t, s))
	for _, p := range []string{s.layout.dataDir, s.layout.tenantsRoot, dir, dbPath(dir), blobsPath(dir)} {
		if err := private(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if err := privateAncestors(dir); err != nil {
		t.Error(err)
	}
}

// Acquire never waits forever: with every slot held, it fails with
// ErrPoolExhausted after AcquireWait, or at the caller's own deadline.
func TestAcquireFailsLoudlyWhenThePoolIsExhausted(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, func(o *Options) {
		o.MaxOpen = 1
		o.AcquireWait = 200 * time.Millisecond
	})
	a, b := createTenant(t, s), createTenant(t, s)
	_, release, err := s.Acquire(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	start := time.Now()
	_, _, err = s.Acquire(ctx, b) // no deadline: AcquireWait applies
	if !errors.Is(err, ErrPoolExhausted) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want ErrPoolExhausted wrapping context.DeadlineExceeded", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("Acquire waited %v; it must give up after about AcquireWait", waited)
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, _, err := s.Acquire(short, b); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("with the caller's deadline: error = %v, want ErrPoolExhausted", err)
	}

	release()
	acquire(t, s, b) // a freed slot is usable again
}

func TestDefaultAcquireWaitIsBounded(t *testing.T) {
	s, _ := newTestStore(t)
	if s.acquireWait != DefaultAcquireWait || DefaultAcquireWait <= 0 || DefaultAcquireWait > time.Minute {
		t.Fatalf("acquire wait = %v, default %v: it must be positive and bounded", s.acquireWait, DefaultAcquireWait)
	}
}
