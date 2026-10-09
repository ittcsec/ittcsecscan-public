//go:build unix

package store

import (
	"os"
	"testing"
)

// Property 3 on Unix: permissions that let other accounts in are refused.
func TestExposedTenantFilesAreRefusedUnix(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(s *Store, dir string) string
		mode os.FileMode
	}{
		{"database readable by others", func(_ *Store, dir string) string { return dbPath(dir) }, 0o644},
		{"tenant directory readable by others", func(_ *Store, dir string) string { return dir }, 0o755},
		{"blobs directory readable by others", func(_ *Store, dir string) string { return blobsPath(dir) }, 0o755},
		{"tenants root writable by others", func(s *Store, _ string) string { return s.layout.tenantsRoot }, 0o777},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			a := createTenant(t, s)
			p := tc.path(s, tenantDir(t, s, a))
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			requireRefused(t, s, a, ErrExposed)
		})
	}
}
