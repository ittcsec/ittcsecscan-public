package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"runtime"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/repo"
)

func readSettings(t *testing.T, tn *Tenant) repo.Settings {
	t.Helper()
	var s repo.Settings
	err := tn.View(context.Background(), func(r repo.Reader) error {
		var err error
		s, err = r.Settings().Get(context.Background())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUpdateCommitsAndViewReads(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})

	if def := readSettings(t, tn); def.RetentionScans != 30 || def.DisplayName != "" {
		t.Fatalf("default settings = %+v, want {30, \"\"}", def)
	}
	if err := tn.Update(ctx, func(w repo.Writer) error {
		if err := w.Settings().SetRetentionScans(ctx, 10); err != nil {
			return err
		}
		return w.Settings().SetDisplayName(ctx, "Acme prod")
	}); err != nil {
		t.Fatal(err)
	}
	if got := readSettings(t, tn); got.RetentionScans != 10 || got.DisplayName != "Acme prod" {
		t.Errorf("after update, settings = %+v, want {10, Acme prod}", got)
	}

	// The fixture entity reads back through View, mapped to a model value.
	stableID := model.StableID(readFixture(t, tn)[0].stableID)
	var ent model.Entity
	err := tn.View(ctx, func(r repo.Reader) error {
		var err error
		ent, err = r.Entities().Get(ctx, stableID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if ent.ID != stableID || ent.NativeID != "arn:aws:iam::111111111111:role/app" || ent.Name != "app" ||
		ent.Provider != model.AWS || ent.Type != model.NodeRole || ent.SchemaVersion != model.SchemaVersion {
		t.Errorf("entity = %+v", ent)
	}
	// A valid but unknown stable ID is ErrNotFound; a malformed one too.
	err = tn.View(ctx, func(r repo.Reader) error {
		if _, err := r.Entities().Get(ctx, model.StableID(strings.Repeat("0", 64))); !errors.Is(err, repo.ErrNotFound) {
			t.Errorf("unknown id: err = %v, want ErrNotFound", err)
		}
		if _, err := r.Entities().Get(ctx, model.StableID("not-hex")); !errors.Is(err, repo.ErrNotFound) {
			t.Errorf("malformed id: err = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Update never leaves a partial write: a returned error, a cancelled context,
// and a panic each roll back, and the tenant is left exactly as it was
// (ADR-0014 §3). This is the general form of the guarantee PR #18's
// TestFirstScanCancelledMidwayIsClean proved for the bulk load.
func TestUpdateRollsBackOnFailure(t *testing.T) {
	newTenant := func() *Tenant {
		s, _ := newTestStore(t)
		return acquire(t, s, createTenant(t, s))
	}
	// write sets both settings away from their defaults; a failing Update must
	// undo it.
	write := func(ctx context.Context, w repo.Writer) error {
		if err := w.Settings().SetRetentionScans(ctx, 7); err != nil {
			return err
		}
		return w.Settings().SetDisplayName(ctx, "temporary")
	}
	assertDefault := func(t *testing.T, tn *Tenant) {
		t.Helper()
		if s := readSettings(t, tn); s.RetentionScans != 30 || s.DisplayName != "" {
			t.Errorf("after a failed update, settings = %+v, want the default {30, \"\"}", s)
		}
	}
	errBoom := errors.New("boom")

	t.Run("returned error", func(t *testing.T) {
		tn := newTenant()
		err := tn.Update(context.Background(), func(w repo.Writer) error {
			if err := write(context.Background(), w); err != nil {
				return err
			}
			return errBoom
		})
		if !errors.Is(err, errBoom) {
			t.Fatalf("Update = %v, want boom", err)
		}
		assertDefault(t, tn)
	})

	t.Run("cancelled context", func(t *testing.T) {
		tn := newTenant()
		ctx, cancel := context.WithCancel(context.Background())
		err := tn.Update(ctx, func(w repo.Writer) error {
			if err := write(ctx, w); err != nil {
				return err
			}
			cancel() // cancel after the writes, before the commit
			return nil
		})
		if err == nil {
			t.Fatal("a cancelled update was committed")
		}
		assertDefault(t, tn)
	})

	t.Run("panic", func(t *testing.T) {
		tn := newTenant()
		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panic did not propagate out of Update")
				}
			}()
			_ = tn.Update(context.Background(), func(w repo.Writer) error {
				if err := write(context.Background(), w); err != nil {
					return err
				}
				panic("boom inside update")
			})
			t.Error("Update returned instead of propagating the panic")
		}()
		assertDefault(t, tn)
	})
}

// TestUpdateCancelDoesNotPoisonConnection is the regression guard for the
// cancelled-transaction bug fixed in View/Update: a cancelled Update must fully
// roll its transaction back on the tenant's single shared connection before it
// returns, so the next operation can open its own transaction on that same
// connection. Before the fix, database/sql spawned its own goroutine to roll
// the transaction back when the context was cancelled; that asynchronous
// rollback raced the explicit synchronous Rollback, database/sql could hand the
// connection to the next operation before the driver-level ROLLBACK finished,
// and the follow-up BeginTx failed with "cannot start a transaction within a
// transaction". The failure is a data race, so it is reliable only under the
// race detector: this test runs the cancel-then-read cycle many times on one
// tenant to widen the window, and CI's -race job is the authoritative check.
func TestUpdateCancelDoesNotPoisonConnection(t *testing.T) {
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	for i := 0; i < 2000; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		err := tn.Update(ctx, func(w repo.Writer) error {
			if err := w.Settings().SetDisplayName(ctx, "temporary"); err != nil {
				return err
			}
			cancel() // cancel after the write, before the commit
			// Yield so database/sql's context-cancellation goroutine can start
			// its asynchronous rollback before this function returns. Without the
			// fix that async rollback then races the shared connection's reuse
			// below; the yield plus many iterations widens the window so the
			// race detector surfaces it.
			runtime.Gosched()
			return nil
		})
		if err == nil {
			t.Fatalf("iteration %d: a cancelled update was committed", i)
		}
		// Reuse the shared connection immediately. Before the fix this begin
		// could hit the in-flight async rollback and fail with the nested-
		// transaction error; two begins per iteration widen the window. The
		// cancelled write must also have rolled back, so the name is the default.
		for r := 0; r < 2; r++ {
			if got := readSettings(t, tn); got.DisplayName != "" {
				t.Fatalf("iteration %d: cancelled update was not rolled back: %+v", i, got)
			}
		}
	}
}

// Tags and attributes round-trip through the entity reader as distinct maps
// (option A: tags stay separate from attributes, ADR-0011 §3). Nothing writes
// them through the repository yet, so the sealed columns are set directly here.
func TestEntityGetReadsTagsAndAttributes(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})
	row := readFixture(t, tn)[0]

	get := func() model.Entity {
		t.Helper()
		var ent model.Entity
		if err := tn.View(ctx, func(r repo.Reader) error {
			var err error
			ent, err = r.Entities().Get(ctx, model.StableID(row.stableID))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return ent
	}
	// Before anything is written, the columns are NULL and read back as nil.
	if before := get(); before.Tags != nil || before.Attributes != nil {
		t.Errorf("unset tags/attributes read back as %v / %v, want nil", before.Tags, before.Attributes)
	}

	tags := map[string]string{"Environment": "prod", "Team": "payments"}
	attrs := map[string]string{"max_session_seconds": "3600"}
	seal := func(f Field, m map[string]string) []byte {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		b, err := tn.SealValue(f, row.node, raw)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := tn.withConn(ctx, func(c *sql.Conn) error {
		_, err := c.ExecContext(ctx, "UPDATE entities SET tags_sealed = ?, attributes_sealed = ? WHERE node_id = ?",
			seal(FieldEntityTags(), tags), seal(FieldEntityAttributes(), attrs), row.node)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	ent := get()
	if !maps.Equal(ent.Tags, tags) {
		t.Errorf("tags = %v, want %v", ent.Tags, tags)
	}
	if !maps.Equal(ent.Attributes, attrs) {
		t.Errorf("attributes = %v, want %v", ent.Attributes, attrs)
	}
}

// A View cannot be used to write: the reader exposes no writer.
func TestViewIsReadOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	tn := acquire(t, s, createTenant(t, s))
	err := tn.View(ctx, func(r repo.Reader) error {
		if _, ok := r.Settings().(repo.SettingsWriter); ok {
			t.Error("a View's Settings() exposes a writer")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
