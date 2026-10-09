package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// KeyUsage reports one tenant's data-key encryption count against the limits
// (B-6). Sealed is how many encryptions have been committed under the tenant's
// data key; at Warn the key should be rotated soon, and at HardStop the store
// refuses to seal until it is.
type KeyUsage struct {
	Tenant   TenantID
	Sealed   int64
	Warn     int64
	HardStop int64
}

// NearLimit reports that the key has reached the warn threshold.
func (u KeyUsage) NearLimit() bool { return u.Sealed >= u.Warn }

// Exhausted reports that the key has reached the hard stop.
func (u KeyUsage) Exhausted() bool { return u.Sealed >= u.HardStop }

// ReadKeyUsage reads every tenant's data-key encryption count under dataDir,
// against the default warn and hard-stop limits (B-6). It is read-only and
// creates nothing: it opens each tenant database immutable, so no journal or WAL
// sidecar is written, which is why doctor can call it. It never unwraps keys, so
// it needs no passphrase. A tenants directory that does not exist yet means no
// tenants, not an error.
func ReadKeyUsage(ctx context.Context, dataDir string) ([]KeyUsage, error) {
	l, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(l.tenantsRoot)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []KeyUsage
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, err := ParseTenantID(e.Name())
		if err != nil {
			continue // not a tenant directory
		}
		count, err := readSealCountReadOnly(ctx, dbPath(filepath.Join(l.tenantsRoot, e.Name())))
		if err != nil {
			return nil, fmt.Errorf("store: reading the key usage of tenant %s: %w", id, err)
		}
		out = append(out, KeyUsage{Tenant: id, Sealed: count, Warn: defaultSealWarn, HardStop: defaultSealHardStop})
	}
	return out, nil
}

// readSealCountReadOnly opens a tenant database immutable and read-only and
// reads its committed encryption count. Immutable means SQLite writes no WAL or
// journal sidecar and takes no locks, so the read leaves the directory
// untouched. Defensive mode and trusted_schema off keep a hostile file from
// running code even on this narrow read.
func readSealCountReadOnly(ctx context.Context, path string) (int64, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_defensive=1&mode=ro&immutable=1")
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "PRAGMA trusted_schema = OFF"); err != nil {
		return 0, err
	}
	var count int64
	if err := conn.QueryRowContext(ctx,
		"SELECT data_key_seal_count FROM tenant WHERE singleton = 1").Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
