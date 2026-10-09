package store

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Property 3 (ADR-0010 §3): filesystem redirection is refused.
//
// These tests may skip for one named reason only: on Windows, an account
// without the symbolic-link privilege cannot create symlinks
// (symlinkNeedsPrivilege). Anywhere else, failing to create a symlink or a
// hard link fails the test, so a green run proves these cases executed.
// Junctions, which need no privilege, are tested in redirect_windows_test.go.

func requireRefused(t *testing.T, s *Store, id TenantID, want error) {
	t.Helper()
	if _, _, err := s.Acquire(context.Background(), id); !errors.Is(err, want) {
		t.Fatalf("Acquire(%s): error = %v, want %v", id, err, want)
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if symlinkNeedsPrivilege(err) {
		t.Skipf("skipped: this Windows account lacks the symbolic-link privilege (%v); the junction tests cover this attack", err)
	}
	t.Fatalf("creating a symlink failed, so this case cannot run: %v", err)
}

func hardLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Link(target, link); err != nil {
		t.Fatalf("creating a hard link failed, so this case cannot run: %v", err)
	}
}

func TestSymlinkedTenantDirectoryIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := createTenant(t, s), createTenant(t, s)
	dirA := tenantDir(t, s, a)
	if err := os.Rename(dirA, dirA+"-moved"); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, tenantDir(t, s, b), dirA)
	requireRefused(t, s, a, ErrUnsafePath)
	acquire(t, s, b)
}

func TestSymlinkedTenantsRootIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a := createTenant(t, s)
	root := s.layout.tenantsRoot
	if err := os.Rename(root, root+"-moved"); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, root+"-moved", root)
	requireRefused(t, s, a, ErrUnsafePath)
}

func TestSymlinkedDatabaseIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := createTenant(t, s), createTenant(t, s)
	dbA := dbPath(tenantDir(t, s, a))
	if err := os.Rename(dbA, dbA+"-moved"); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, dbPath(tenantDir(t, s, b)), dbA)
	requireRefused(t, s, a, ErrUnsafePath)
}

func TestHardLinkedDatabaseIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := createTenant(t, s), createTenant(t, s)
	dbA, dbB := dbPath(tenantDir(t, s, a)), dbPath(tenantDir(t, s, b))
	if err := os.Remove(dbA); err != nil {
		t.Fatal(err)
	}
	hardLink(t, dbB, dbA)
	requireRefused(t, s, a, ErrUnsafePath)
	// B's file now has a second name, so B is refused too.
	requireRefused(t, s, b, ErrUnsafePath)
}

func TestLinkedSidecarIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := createTenant(t, s), createTenant(t, s)
	hardLink(t, dbPath(tenantDir(t, s, b)), dbPath(tenantDir(t, s, a))+"-wal")
	requireRefused(t, s, a, ErrUnsafePath)
}
