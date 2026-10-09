package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// The per-data-key encryption limit (B-6, ADR-0011 §3). AES-256-GCM with
// random 96-bit nonces is safe to about 2^32 encryptions per key; the hard
// stop is 16x below that, and the warning is one power of two below the stop.
// A tenant's data key is never replaced except by rotation, so the count is
// per tenant and only ever rises.
const (
	defaultSealHardStop = int64(1) << 28 // 268,435,456
	defaultSealWarn     = int64(1) << 27 // 134,217,728
)

// ErrKeyExhausted reports that a tenant's data key has reached its encryption
// limit and must be rotated before more values can be sealed (B-6). It is
// returned before any further encryption is performed.
var ErrKeyExhausted = errors.New("store: the tenant's data key has reached its encryption limit and must be rotated")

// reservation is a committed, non-refundable claim on encryption slots under a
// tenant's data key. Its slots were added to data_key_seal_count and committed
// before any of the encryptions they authorise, so a rolled-back write can
// never lower the count: the count can only over-report, never under-report,
// the encryptions performed. Every counted encryption consumes one slot, so
// the encryptions performed can never exceed the committed count, which can
// never exceed the hard stop.
type reservation struct {
	balance   int64 // slots left to consume; never negative
	nearLimit bool  // the commit crossed the warn threshold
}

// NearLimit reports whether reserving these slots crossed the warn threshold,
// so the operator can be told to rotate the key soon.
func (r *reservation) NearLimit() bool { return r.nearLimit }

// take consumes one slot for one encryption. When the reservation is spent it
// refuses, so a caller must reserve more before sealing again.
func (r *reservation) take() error {
	if r.balance <= 0 {
		return fmt.Errorf("%w: reservation exhausted", ErrKeyExhausted)
	}
	r.balance--
	return nil
}

// reserveSeals commits a claim on n encryption slots under the tenant's data
// key, in its own transaction, so the claim survives a later rollback (B-6).
// It refuses, changing nothing, if the claim would pass the hard stop. Call it
// before the Update that performs the encryptions, never inside one: it takes
// the tenant's connection, which an open Update already holds.
func (t *Tenant) reserveSeals(ctx context.Context, n int64) (*reservation, error) {
	if n < 0 {
		return nil, fmt.Errorf("store: cannot reserve %d encryption slots", n)
	}
	if n == 0 {
		return &reservation{}, nil
	}
	res := &reservation{}
	var committed int64 // the count after this reservation commits
	err := t.withConn(ctx, func(c *sql.Conn) error {
		tx, err := c.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT data_key_seal_count FROM tenant WHERE singleton = 1").Scan(&count); err != nil {
			return errors.Join(err, tx.Rollback())
		}
		if count+n > t.sealHardStop {
			return errors.Join(
				fmt.Errorf("%w: %d committed, %d more would pass the limit of %d", ErrKeyExhausted, count, n, t.sealHardStop),
				tx.Rollback())
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tenant SET data_key_seal_count = data_key_seal_count + ? WHERE singleton = 1", n); err != nil {
			return errors.Join(err, tx.Rollback())
		}
		res.balance = n
		res.nearLimit = count < t.sealWarn && count+n >= t.sealWarn
		committed = count + n
		return tx.Commit()
	})
	if err != nil {
		return nil, err
	}
	// Warn once, at the reservation that crosses the threshold; opening the
	// tenant warns again for a key that is already past it (B-6).
	if res.nearLimit {
		t.warnNearLimit(committed)
	}
	return res, nil
}

// SealCounted performs one reserved encryption: it consumes a reservation slot,
// then seals (ADR-0013). Without a slot it refuses with ErrKeyExhausted before
// encrypting, so the number of encryptions under a data key can never pass the
// reserved slots, and therefore never the hard stop (B-6). The reservation
// must come from reserveSeals, committed before this call.
func (t *Tenant) SealCounted(res *reservation, f Field, row int64, plaintext []byte) ([]byte, error) {
	if res == nil {
		return nil, fmt.Errorf("%w: no reservation", ErrKeyExhausted)
	}
	if err := res.take(); err != nil {
		return nil, err
	}
	return t.SealValue(f, row, plaintext)
}

// sealCount reads the committed encryption count for the tenant's data key.
func (t *Tenant) sealCount(ctx context.Context) (int64, error) {
	var count int64
	err := t.withConn(ctx, func(c *sql.Conn) error {
		return c.QueryRowContext(ctx, "SELECT data_key_seal_count FROM tenant WHERE singleton = 1").Scan(&count)
	})
	return count, err
}
