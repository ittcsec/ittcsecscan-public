// Package receiptstore adapts a store tenant to the remediation executor's ReceiptSink, so
// an executed remediation's receipt is persisted as an immutable, per-tenant, sealed row
// (ADR-0029). It is the glue the fix-apply command wires: the
// executor stays unaware of the store, the store stays unaware of the executor, and this
// small package maps one onto the other.
package receiptstore

import (
	"context"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/remediate/execute"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// Sink persists executor receipts into a tenant's immutable remediation-receipt log.
type Sink struct {
	tenant *store.Tenant
	now    func() time.Time
}

// New returns a sink that writes to the given tenant. now supplies the receipt timestamp
// (the CLI layer holds the clock); nil uses time.Now.
func New(t *store.Tenant, now func() time.Time) *Sink {
	if now == nil {
		now = time.Now
	}
	return &Sink{tenant: t, now: now}
}

// Record maps the executor's receipt onto the store's sealed, append-only record.
func (s *Sink) Record(ctx context.Context, r execute.Receipt) error {
	return s.tenant.AddRemediationReceipt(ctx, store.RemediationReceipt{
		Entity:     r.Entity,
		Rule:       r.Rule.RuleID,
		PlanHash:   r.PlanHash,
		Profile:    string(r.Profile),
		Action:     r.Action.Summary,
		Applied:    r.Applied,
		PriorState: r.PriorState,
		Refusal:    r.Refusal,
		At:         s.now().UTC(),
	})
}

// Sink satisfies the executor's ReceiptSink.
var _ execute.ReceiptSink = (*Sink)(nil)
