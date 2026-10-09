package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// End to end: a tenant whose data key has reached the warn threshold makes
// doctor report the store.data_keys check as a warning (B-6). This exercises
// the whole chain: the read-only key-usage read, the CLI wiring, and the check.
func TestDoctorReportsNearLimitDataKey(t *testing.T) {
	ctx := context.Background()
	dataDir := filepath.Join(t.TempDir(), "data")

	mk, err := store.NewMasterKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.NewStaticMasterKeys(mk)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(store.Options{DataDir: dataDir, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Push the data key to the warn threshold (2^27); the store is closed, so
	// this stands in for many committed reservations without running them.
	dbPath := filepath.Join(dataDir, "tenants", id.String(), "store.db")
	db, err := sql.Open("sqlite", dbPath+"?_defensive=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE tenant SET data_key_seal_count = 134217728 WHERE singleton = 1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	env := hermetic(t, map[string]string{config.EnvDataDir: dataDir})
	rep := decodeDoctor(t, invoke(t, env, "doctor", "--json"))
	if got := checkStatus(rep, "store.data_keys"); got != "warn" {
		t.Errorf("store.data_keys = %q, want warn (a data key at its limit must warn)", got)
	}
}
