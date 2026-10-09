package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/fsperm"
)

// testDataDir returns a data directory for one test. The store refuses
// folders that other accounts can replace, so when the system temporary
// directory is not private (as on some Windows machines), the test fails with
// guidance instead of weakening the check under test.
func testDataDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	reps, err := fsperm.InspectAncestors(filepath.Join(base, "probe"))
	if err != nil || len(reps) > 0 {
		t.Fatalf("temporary directory %s is not private: another account can replace a folder above it, or it could not be checked (%v). "+
			"Point TMPDIR (Unix) or TEMP and TMP (Windows) at an owner-only folder to run the store tests.", base, err)
	}
	return filepath.Join(base, "data")
}

func testMasterKey(t *testing.T, gen uint32) MasterKey {
	t.Helper()
	b := make([]byte, keyLen)
	_, _ = rand.Read(b)
	k, err := NewMasterKey(gen, b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func staticKeys(t *testing.T, keys ...MasterKey) *StaticMasterKeys {
	t.Helper()
	s, err := NewStaticMasterKeys(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTestStore opens a store in a fresh private data directory with one
// master key, generation 1.
func newTestStore(t *testing.T, opts ...func(*Options)) (*Store, Options) {
	t.Helper()
	o := Options{DataDir: testDataDir(t), Keys: staticKeys(t, testMasterKey(t, 1))}
	for _, f := range opts {
		f(&o)
	}
	return openStore(t, o), o
}

func openStore(t *testing.T, o Options) *Store {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func createTenant(t *testing.T, s *Store) TenantID {
	t.Helper()
	id, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return id
}

// acquire opens a tenant for the rest of the test.
func acquire(t *testing.T, s *Store, id TenantID) *Tenant {
	t.Helper()
	tn, release, err := s.Acquire(context.Background(), id)
	if err != nil {
		t.Fatalf("Acquire(%s): %v", id, err)
	}
	t.Cleanup(release)
	return tn
}

func tenantDir(t *testing.T, s *Store, id TenantID) string {
	t.Helper()
	d, err := s.layout.dir(id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// exec runs statements on a tenant's hardened connection.
func exec(t *testing.T, tn *Tenant, stmts ...string) {
	t.Helper()
	ctx := context.Background()
	err := tn.withConn(ctx, func(c *sql.Conn) error {
		for _, s := range stmts {
			if _, err := c.ExecContext(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// rawExec opens a database file directly, bypassing every store check, the
// way an attacker with file access could.
func rawExec(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, s := range stmts {
		if _, err := db.ExecContext(context.Background(), s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}
