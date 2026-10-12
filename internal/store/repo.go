package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/repo"
)

// View runs fn against a single consistent read snapshot of the tenant
// (ADR-0014 §3). Every repository fn reaches through the repo.Reader reads
// that one snapshot, so a whole report sees one state. It never writes.
func (t *Tenant) View(ctx context.Context, fn func(repo.Reader) error) error {
	return t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) (err error) {
			// Begin with a non-cancellable context so database/sql does not spawn
			// its own goroutine to roll the transaction back when ctx is cancelled.
			// That asynchronous rollback races this function's own synchronous
			// Rollback on the tenant's single shared connection: database/sql can
			// release the connection before the driver-level ROLLBACK finishes, and
			// the next operation's BeginTx then fails with "cannot start a
			// transaction within a transaction". Cancellation is still honoured, by
			// the queries, which run under the cancellable ctx via repoView.
			tx, err := c.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, tx.Rollback()) }()
			return fn(&repoView{ctx: ctx, tx: tx, k: k})
		})
	})
}

// Update runs fn in one read-write transaction and commits it as a unit
// (ADR-0014 §3). Every repository fn reaches through the repo.Writer shares
// the transaction, so a scan ingest is atomic. It never leaves a partial
// write:
//   - it commits only when fn returns nil and the context is not done;
//   - a returned error, or a cancelled context, rolls back;
//   - a panic in fn rolls back during unwinding and is then re-raised.
func (t *Tenant) Update(ctx context.Context, fn func(repo.Writer) error) error {
	return t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) error {
			// Begin with a non-cancellable context: database/sql would otherwise
			// roll this transaction back from its own goroutine when ctx is
			// cancelled, racing the explicit Rollback below on the tenant's single
			// shared connection and leaving a half-closed transaction behind, so
			// the next BeginTx on that connection fails with "cannot start a
			// transaction within a transaction". We handle cancellation ourselves,
			// synchronously (the ctx.Err() check rolls back before returning), and
			// the queries inside fn still run under the cancellable ctx.
			tx, err := c.BeginTx(context.WithoutCancel(ctx), nil)
			if err != nil {
				return err
			}
			w := &repoWriter{repoView{ctx: ctx, tx: tx, k: k}}
			if err := runUpdate(tx, w, fn); err != nil {
				return errors.Join(err, tx.Rollback())
			}
			if err := ctx.Err(); err != nil {
				return errors.Join(err, tx.Rollback())
			}
			return tx.Commit()
		})
	})
}

// runUpdate calls fn(w). If fn panics, the transaction is rolled back during
// the unwinding and the panic is re-raised, so a panicking caller never leaves
// a half-written transaction either.
func runUpdate(tx *sql.Tx, w *repoWriter, fn func(repo.Writer) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	return fn(w)
}

// execQuerier is the part of *sql.Tx the repositories use.
type execQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// repoView binds the repositories to one transaction and the tenant's keys.
type repoView struct {
	ctx context.Context
	tx  execQuerier
	k   *tenantKeys
}

func (v *repoView) Settings() repo.SettingsReader { return &settingsReader{v} }
func (v *repoView) Entities() repo.EntityReader   { return &entityRepo{v} }

// repoWriter adds the write repositories. Entities reads are promoted from
// repoView.
type repoWriter struct{ repoView }

// Settings returns a writer. A View returns only a *settingsReader, which does
// not satisfy repo.SettingsWriter, so a read snapshot cannot be downcast into
// a writer.
func (w *repoWriter) Settings() repo.SettingsWriter {
	return &settingsWriter{settingsReader{&w.repoView}}
}

// settingsReader reads the tenant identity row's settings.
type settingsReader struct{ v *repoView }

func (s *settingsReader) Get(ctx context.Context) (repo.Settings, error) {
	var retention int
	var sealed []byte
	if err := s.v.tx.QueryRowContext(ctx, "SELECT retention_scans, display_name_sealed FROM tenant WHERE singleton = 1").Scan(&retention, &sealed); err != nil {
		return repo.Settings{}, err
	}
	name := ""
	if sealed != nil {
		pt, err := s.v.k.open(FieldTenantDisplayName(), 1, sealed)
		if err != nil {
			return repo.Settings{}, err
		}
		name = string(pt)
	}
	return repo.Settings{RetentionScans: retention, DisplayName: name}, nil
}

// settingsWriter reads and changes the tenant's settings.
type settingsWriter struct{ settingsReader }

func (s *settingsWriter) SetRetentionScans(ctx context.Context, n int) error {
	// The tenant CHECK enforces 1..30; a bad value is refused by SQLite.
	return s.exec(ctx, "UPDATE tenant SET retention_scans = ? WHERE singleton = 1", n)
}

func (s *settingsWriter) SetDisplayName(ctx context.Context, name string) error {
	sealed, err := s.v.k.seal(FieldTenantDisplayName(), 1, []byte(name))
	if err != nil {
		return err
	}
	return s.exec(ctx, "UPDATE tenant SET display_name_sealed = ? WHERE singleton = 1", sealed)
}

// exec runs a single-row identity update and checks that exactly one row
// changed. query is a constant statement from this file; value is bound.
func (s *settingsWriter) exec(ctx context.Context, query string, value any) error {
	res, err := s.v.tx.ExecContext(ctx, query, value)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("store: updating tenant settings changed %d rows (%w)", n, err)
	}
	return nil
}

// entityRepo reads entities by stable ID, mapping store rows to model values.
type entityRepo struct{ v *repoView }

func (r *entityRepo) Get(ctx context.Context, id model.StableID) (model.Entity, error) {
	if !id.Valid() {
		return model.Entity{}, fmt.Errorf("%w: %q is not a stable ID", repo.ErrNotFound, id)
	}
	sid, err := hex.DecodeString(string(id))
	if err != nil {
		return model.Entity{}, fmt.Errorf("%w: %w", repo.ErrNotFound, err)
	}
	var node, provider, typ, criticality, firstAt, lastAt int64
	var nativeSealed, nameSealed, tagsSealed, attrsSealed []byte
	err = r.v.tx.QueryRowContext(ctx,
		"SELECT node_id, provider, type, native_id_sealed, name_sealed, tags_sealed, attributes_sealed, criticality, first_seen_at, last_seen_at FROM entities WHERE stable_id = ?", sid).
		Scan(&node, &provider, &typ, &nativeSealed, &nameSealed, &tagsSealed, &attrsSealed, &criticality, &firstAt, &lastAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Entity{}, repo.ErrNotFound
	}
	if err != nil {
		return model.Entity{}, err
	}
	providerName, ok := providerCodes.name(provider)
	typeName, ok2 := nodeTypeCodes.name(typ)
	if !ok || !ok2 {
		return model.Entity{}, fmt.Errorf("%w: entity has provider code %d and type code %d", ErrForeignFile, provider, typ)
	}
	native, err := r.v.k.open(FieldEntityNativeID(), node, nativeSealed)
	if err != nil {
		return model.Entity{}, err
	}
	name := ""
	if nameSealed != nil {
		pt, err := r.v.k.open(FieldEntityName(), node, nameSealed)
		if err != nil {
			return model.Entity{}, err
		}
		name = string(pt)
	}
	tags, err := r.openMap(FieldEntityTags(), node, tagsSealed)
	if err != nil {
		return model.Entity{}, err
	}
	attributes, err := r.openMap(FieldEntityAttributes(), node, attrsSealed)
	if err != nil {
		return model.Entity{}, err
	}
	return model.Entity{
		SchemaVersion: model.SchemaVersion,
		ID:            id,
		Provider:      model.Provider(providerName),
		Type:          model.NodeType(typeName),
		NativeID:      string(native),
		Name:          name,
		Tags:          tags,
		Attributes:    attributes,
		Criticality:   int(criticality),
		FirstSeen:     time.UnixMilli(firstAt).UTC(),
		LastSeen:      time.UnixMilli(lastAt).UTC(),
	}, nil
}

// openMap decrypts a sealed JSON string→string map, or returns nil when the
// column is NULL (nothing written yet).
func (r *entityRepo) openMap(f Field, row int64, sealed []byte) (map[string]string, error) {
	if sealed == nil {
		return nil, nil
	}
	pt, err := r.v.k.open(f, row, sealed)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrForeignFile, err)
	}
	return m, nil
}
