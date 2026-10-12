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

// RemediationReceipt is one immutable record of an executed remediation, written at the
// point of verification (ADR-0029). PriorState is the resource's
// configuration as it was immediately before the change, so an operator can restore it. It
// is a store-level type so the store does not import the remediation package; the executor
// maps its own receipt onto this.
type RemediationReceipt struct {
	Entity     model.StableID
	Rule       string
	PlanHash   string
	Profile    string
	Action     string
	Applied    bool
	PriorState string
	Refusal    string
	At         time.Time
}

// AddRemediationReceipt appends one immutable remediation receipt. It is append-only: a row
// is inserted, never updated or deleted, so the audit trail is intact. PriorState and any
// refusal are sealed with the tenant data key, bound to the new row's id, for the same
// at-rest protection as every other sensitive value. The caller stamps At (the CLI layer
// holds the clock).
func (t *Tenant) AddRemediationReceipt(ctx context.Context, r RemediationReceipt) error {
	if !r.Entity.Valid() {
		return fmt.Errorf("store: receipt target %q is not a stable id", r.Entity)
	}
	if r.Rule == "" {
		return errors.New("store: receipt needs a rule")
	}
	if r.PlanHash == "" {
		return errors.New("store: receipt needs a plan hash")
	}
	if r.Profile == "" {
		return errors.New("store: receipt needs a credential profile")
	}
	if r.At.IsZero() {
		return errors.New("store: receipt needs a timestamp")
	}
	sid, err := hex.DecodeString(string(r.Entity))
	if err != nil {
		return fmt.Errorf("store: receipt target: %w", err)
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
				"SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'remediation_receipts'), 0)").Scan(&seq); err != nil {
				return err
			}
			id := seq + 1
			var priorSealed, refusalSealed []byte
			if r.PriorState != "" {
				if priorSealed, err = k.seal(FieldReceiptPriorState(), id, []byte(r.PriorState)); err != nil {
					return err
				}
			}
			if r.Refusal != "" {
				if refusalSealed, err = k.seal(FieldReceiptRefusal(), id, []byte(r.Refusal)); err != nil {
					return err
				}
			}
			applied := 0
			if r.Applied {
				applied = 1
			}
			if _, err = tx.ExecContext(ctx,
				`INSERT INTO remediation_receipts
				 (receipt_id, tenant_id, stable_id, rule, plan_hash, profile, action, applied, prior_state_sealed, refusal_sealed, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				id, k.id, sid, r.Rule, r.PlanHash, r.Profile, r.Action, applied, priorSealed, refusalSealed, r.At.UnixMilli()); err != nil {
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

// RemediationReceipts returns the full receipt audit history, oldest first. Sealed prior
// state and refusal are decrypted here.
func (t *Tenant) RemediationReceipts(ctx context.Context) ([]RemediationReceipt, error) {
	var out []RemediationReceipt
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
				`SELECT receipt_id, stable_id, rule, plan_hash, profile, action, applied, prior_state_sealed, refusal_sealed, created_at
				 FROM remediation_receipts ORDER BY receipt_id ASC`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id, applied, createdAt int64
				var sid, priorSealed, refusalSealed []byte
				var rule, planHash, profile, action string
				if err := rows.Scan(&id, &sid, &rule, &planHash, &profile, &action, &applied, &priorSealed, &refusalSealed, &createdAt); err != nil {
					return err
				}
				prior := ""
				if priorSealed != nil {
					pt, err := k.open(FieldReceiptPriorState(), id, priorSealed)
					if err != nil {
						return err
					}
					prior = string(pt)
				}
				refusal := ""
				if refusalSealed != nil {
					pt, err := k.open(FieldReceiptRefusal(), id, refusalSealed)
					if err != nil {
						return err
					}
					refusal = string(pt)
				}
				out = append(out, RemediationReceipt{
					Entity:     model.StableID(hex.EncodeToString(sid)),
					Rule:       rule,
					PlanHash:   planHash,
					Profile:    profile,
					Action:     action,
					Applied:    applied == 1,
					PriorState: prior,
					Refusal:    refusal,
					At:         time.UnixMilli(createdAt).UTC(),
				})
			}
			return rows.Err()
		})
	})
	return out, err
}
