package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// AddCriticalityOverride appends one audited business-criticality override for an
// entity (ADR-0025 section 4). It is append-only: a row is inserted, never updated
// or deleted, so the full audit history is retained and the highest override_id per
// entity is the effective one. The actor and reason are sealed with the tenant data
// key, bound to the new row's id, for the same at-rest protection as every other
// human-supplied value. The caller stamps At (the CLI layer holds the clock; the
// classification engine never does).
func (t *Tenant) AddCriticalityOverride(ctx context.Context, ov model.CriticalityOverride) error {
	if !ov.Entity.Valid() {
		return fmt.Errorf("store: override target %q is not a stable id", ov.Entity)
	}
	if ov.Criticality < 1 {
		return fmt.Errorf("store: override criticality must be at least 1, got %d", ov.Criticality)
	}
	if ov.Actor == "" {
		return errors.New("store: override needs an actor")
	}
	if ov.At.IsZero() {
		return errors.New("store: override needs a timestamp")
	}
	sid, err := hex.DecodeString(string(ov.Entity))
	if err != nil {
		return fmt.Errorf("store: override target: %w", err)
	}
	return t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) (err error) {
			// Non-cancellable to avoid the shared-connection rollback race; see
			// the comment on BeginTx in (*Tenant).Update (repo.go).
			tx, err := c.BeginTx(context.WithoutCancel(ctx), nil)
			if err != nil {
				return err
			}
			committed := false
			defer func() {
				if !committed {
					err = errors.Join(err, tx.Rollback())
				}
			}()
			var seq int64
			if err = tx.QueryRowContext(ctx,
				"SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'criticality_overrides'), 0)").Scan(&seq); err != nil {
				return err
			}
			id := seq + 1
			actorSealed, err := k.seal(FieldOverrideActor(), id, []byte(ov.Actor))
			if err != nil {
				return err
			}
			var reasonSealed []byte
			if ov.Reason != "" {
				if reasonSealed, err = k.seal(FieldOverrideReason(), id, []byte(ov.Reason)); err != nil {
					return err
				}
			}
			if _, err = tx.ExecContext(ctx,
				`INSERT INTO criticality_overrides (override_id, tenant_id, stable_id, criticality, actor_sealed, reason_sealed, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, k.id, sid, ov.Criticality, actorSealed, reasonSealed, ov.At.UnixMilli()); err != nil {
				return err
			}
			// The begin is non-cancellable, so roll back on a late cancel rather
			// than committing. committed is still false, so the defer rolls back.
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			committed = true
			return nil
		})
	})
}

// CriticalityOverrides returns the full override audit history, oldest first (by
// append order). The caller sees every decision; the last override for an entity is
// the effective one. Sealed actor and reason are decrypted here.
func (t *Tenant) CriticalityOverrides(ctx context.Context) ([]model.CriticalityOverride, error) {
	var out []model.CriticalityOverride
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return t.withKeys(func(k *tenantKeys) (err error) {
			// Non-cancellable to avoid the shared-connection rollback race; see
			// the comment on BeginTx in (*Tenant).View (repo.go).
			tx, err := c.BeginTx(context.WithoutCancel(ctx), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				return err
			}
			defer func() { err = errors.Join(err, tx.Rollback()) }()
			rows, err := tx.QueryContext(ctx,
				`SELECT override_id, stable_id, criticality, actor_sealed, reason_sealed, created_at
				 FROM criticality_overrides ORDER BY override_id ASC`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, criticality, createdAt int64
				var sid, actorSealed, reasonSealed []byte
				if err := rows.Scan(&id, &sid, &criticality, &actorSealed, &reasonSealed, &createdAt); err != nil {
					return err
				}
				actor, err := k.open(FieldOverrideActor(), id, actorSealed)
				if err != nil {
					return err
				}
				reason := ""
				if reasonSealed != nil {
					pt, err := k.open(FieldOverrideReason(), id, reasonSealed)
					if err != nil {
						return err
					}
					reason = string(pt)
				}
				out = append(out, model.CriticalityOverride{
					Entity:      model.StableID(hex.EncodeToString(sid)),
					Criticality: int(criticality),
					Actor:       string(actor),
					Reason:      reason,
					At:          time.UnixMilli(createdAt).UTC(),
				})
			}
			return rows.Err()
		})
	})
	return out, err
}
