package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	tenantsDirName  = "tenants"
	dbFileName      = "store.db"
	blobsDirName    = "blobs"
	backupsDirName  = "backups"
	migrateLockName = "migrate.lock"
)

// layout maps tenant IDs to their directories under <data_dir>/tenants.
type layout struct {
	dataDir     string
	tenantsRoot string
}

func newLayout(dataDir string) (layout, error) {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return layout{}, errors.New("store: the data directory must be an absolute path")
	}
	clean := filepath.Clean(dataDir)
	// The SQLite driver reads '?' as the start of connection parameters.
	if strings.ContainsAny(clean, "?#") {
		return layout{}, errors.New("store: the data directory path must not contain '?' or '#'")
	}
	return layout{dataDir: clean, tenantsRoot: filepath.Join(clean, tenantsDirName)}, nil
}

// dir is the only function that turns a tenant ID into a path. It re-validates
// the ID, so a zero or hand-built TenantID can never select a path, and it
// requires the result to be a direct child of the tenants root.
func (l layout) dir(id TenantID) (string, error) {
	if _, err := ParseTenantID(id.String()); err != nil {
		return "", err
	}
	p := filepath.Join(l.tenantsRoot, id.String())
	if filepath.Dir(p) != l.tenantsRoot || filepath.Base(p) != id.String() {
		return "", fmt.Errorf("%w: tenant path resolves outside the tenants root", ErrUnsafePath)
	}
	return p, nil
}

func dbPath(tenantDir string) string    { return filepath.Join(tenantDir, dbFileName) }
func blobsPath(tenantDir string) string { return filepath.Join(tenantDir, blobsDirName) }

func backupsPath(tenantDir string) string { return filepath.Join(tenantDir, backupsDirName) }
func lockPath(tenantDir string) string    { return filepath.Join(tenantDir, migrateLockName) }

// sidecars are the files SQLite keeps next to a WAL-mode database. They are
// checked like the database itself: a linked sidecar would redirect writes.
func sidecars(db string) []string { return []string{db + "-wal", db + "-shm", db + "-journal"} }
