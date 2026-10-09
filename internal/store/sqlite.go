package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// openDB opens the database at path and returns its single connection,
// hardened. The pool never opens a second connection: SetMaxOpenConns(1), and
// the one connection is held for the handle's lifetime.
//
// Defensive mode is opt-in in the driver, so the DSN enables it. The data
// directory may not contain '?' (newLayout), so the parameter cannot be
// confused with the path.
func openDB(ctx context.Context, path string) (*sql.DB, *sql.Conn, error) {
	db, err := sql.Open("sqlite", path+"?_defensive=1")
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, nil, errors.Join(err, db.Close())
	}
	if err := harden(ctx, conn); err != nil {
		return nil, nil, errors.Join(err, conn.Close(), db.Close())
	}
	return db, conn, nil
}

// harden applies and then reads back every connection safety setting of
// ADR-0010 §1. Nothing is trusted until it is verified.
func harden(ctx context.Context, conn *sql.Conn) error {
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, 0); err != nil {
		return fmt.Errorf("%w: limiting attached databases: %w", ErrHardening, err)
	}
	if n, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, -1); err != nil || n != 0 {
		return fmt.Errorf("%w: attached-database limit is %d, want 0 (%w)", ErrHardening, n, err)
	}
	for _, stmt := range []string{
		"PRAGMA trusted_schema = OFF",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA foreign_keys = ON",
		"PRAGMA secure_delete = ON",
		"PRAGMA writable_schema = ON", // must be refused by defensive mode
	} {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrHardening, stmt, err)
		}
	}
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode); err != nil || mode != "wal" {
		return fmt.Errorf("%w: journal mode is %q, want wal (%w)", ErrHardening, mode, err)
	}
	for _, c := range []struct {
		query string
		want  int64
	}{
		{"PRAGMA trusted_schema", 0},
		{"PRAGMA temp_store", 2}, // MEMORY
		{"PRAGMA foreign_keys", 1},
		{"PRAGMA secure_delete", 1},
		{"PRAGMA writable_schema", 0}, // defensive mode is on
	} {
		var got int64
		if err := conn.QueryRowContext(ctx, c.query).Scan(&got); err != nil || got != c.want {
			return fmt.Errorf("%w: %s = %d, want %d (%w)", ErrHardening, c.query, got, c.want, err)
		}
	}
	return nil
}

// identity is the single row of a tenant file's tenant table, written by
// migration 0001.
type identity struct {
	tenantID    string
	schema      int64
	minReader   int64
	generation  uint32
	wrappedData []byte
	wrappedID   []byte
}

// readIdentity refuses a schema containing triggers or views, which could run
// code when read, and then returns the single identity row.
func readIdentity(ctx context.Context, conn *sql.Conn) (identity, error) {
	rows, err := conn.QueryContext(ctx, "SELECT type, name FROM sqlite_schema")
	if err != nil {
		return identity{}, fmt.Errorf("%w: reading schema: %w", ErrForeignFile, err)
	}
	haveTenant := false
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			return identity{}, errors.Join(fmt.Errorf("%w: reading schema: %w", ErrForeignFile, err), rows.Close())
		}
		switch {
		case typ == "trigger" || typ == "view":
			return identity{}, errors.Join(fmt.Errorf("%w: schema contains a %s", ErrForeignFile, typ), rows.Close())
		case typ == "table" && name == "tenant":
			haveTenant = true
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return identity{}, fmt.Errorf("%w: reading schema: %w", ErrForeignFile, err)
	}
	if !haveTenant {
		return identity{}, fmt.Errorf("%w: no tenant identity table", ErrForeignFile)
	}

	var n int
	if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM tenant").Scan(&n); err != nil || n != 1 {
		return identity{}, fmt.Errorf("%w: want exactly one identity row, got %d (%w)", ErrForeignFile, n, err)
	}
	var id identity
	var gen int64
	err = conn.QueryRowContext(ctx,
		"SELECT tenant_id, schema_version, min_reader_version, key_generation, wrapped_data_key, wrapped_id_key FROM tenant WHERE singleton = 1").
		Scan(&id.tenantID, &id.schema, &id.minReader, &gen, &id.wrappedData, &id.wrappedID)
	if err != nil {
		return identity{}, fmt.Errorf("%w: reading identity: %w", ErrForeignFile, err)
	}
	if gen < 1 || gen > int64(^uint32(0)) {
		return identity{}, fmt.Errorf("%w: invalid key generation", ErrForeignFile)
	}
	id.generation = uint32(gen)
	return id, nil
}
