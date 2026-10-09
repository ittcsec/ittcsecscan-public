package store

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The store logs a warning when a data key crosses the encryption warn
// threshold, and again when a tenant already past it is opened (B-6).
func TestSealWarnLogs(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s, o := newTestStore(t, func(o *Options) {
		o.sealHardStop = 100
		o.sealWarn = 5
		o.Logger = logger
	})
	id := createTenant(t, s)
	tn := acquire(t, s, id)
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})
	if strings.Contains(buf.String(), "encryption limit") {
		t.Fatalf("warned before crossing the threshold: %s", buf.String())
	}
	// Reserve enough to cross the warn threshold.
	if _, err := tn.reserveSeals(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "near its encryption limit") || !strings.Contains(buf.String(), id.String()) {
		t.Errorf("no crossing warning logged: %s", buf.String())
	}

	// Opening the tenant afresh (a new store over the same files) warns again,
	// because the key is already past the threshold.
	var buf2 bytes.Buffer
	s2 := openStore(t, Options{
		DataDir: o.DataDir, Keys: o.Keys, sealHardStop: 100, sealWarn: 5,
		Logger: slog.New(slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	acquire(t, s2, id)
	if !strings.Contains(buf2.String(), "near its encryption limit") {
		t.Errorf("opening a past-threshold tenant did not warn: %s", buf2.String())
	}
}

// ReadKeyUsage reports each tenant's committed seal count, and reading it
// creates no journal or WAL sidecar (doctor writes nothing).
func TestReadKeyUsageIsReadOnly(t *testing.T) {
	ctx := context.Background()
	s, o := newTestStore(t)
	id := createTenant(t, s)
	tn := acquire(t, s, id)
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})
	want := sealCountNow(t, tn)
	if want == 0 {
		t.Fatal("the fixture's first scan should have counted some seals")
	}

	// Close the store so the tenant's files are at rest before the read.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(o.DataDir, "tenants", id.String())
	before := dirListing(t, dir)

	usage, err := ReadKeyUsage(ctx, o.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 {
		t.Fatalf("ReadKeyUsage returned %d tenants, want 1", len(usage))
	}
	u := usage[0]
	if u.Tenant != id || u.Sealed != want {
		t.Errorf("usage = %+v, want tenant %s with %d seals", u, id, want)
	}
	if u.Warn != defaultSealWarn || u.HardStop != defaultSealHardStop {
		t.Errorf("limits = warn %d, stop %d, want %d and %d", u.Warn, u.HardStop, defaultSealWarn, defaultSealHardStop)
	}

	if after := dirListing(t, dir); after != before {
		t.Errorf("the read changed the tenant directory:\nbefore: %s\nafter:  %s", before, after)
	}
}

// An absent tenants directory is no tenants, not an error.
func TestReadKeyUsageEmpty(t *testing.T) {
	usage, err := ReadKeyUsage(context.Background(), t.TempDir())
	if err != nil || usage != nil {
		t.Errorf("ReadKeyUsage on an empty dir = (%v, %v), want (nil, nil)", usage, err)
	}
}

func dirListing(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names string
	for _, e := range entries {
		names += e.Name() + "\n"
	}
	return names
}
