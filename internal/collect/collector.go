package collect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// Sink receives everything a collector produces: the graph it found (as
// native-id nodes and links), redacted evidence, and completeness records. An
// accumulating Sink (Scan) gathers them so they are ingested through the store
// in one transaction, keeping the collector free of the store's internals.
type Sink interface {
	Node(Node) error
	Link(Link) error
	Evidence(Envelope) error
	Complete(Completeness) error
}

// Collector reads one slice of one provider, read-only. It is constructed with
// its provider's authenticated read-only clients (built from the credential the
// identity adapter already resolved), so Collect needs only the context and the
// sink. It declares the permissions it requires, which the templates reconcile
// against (ADR-0016).
type Collector interface {
	// ID is a stable identifier, e.g. "collector:aws.iam.roles".
	ID() string
	// Provider is the provider this collector reads.
	Provider() model.Provider
	// Requirements are the permissions this collector needs, credited to its ID.
	Requirements() []permissions.Requirement
	// Collect reads its slice and emits evidence and completeness to the sink.
	// It paginates fully or records Partial, honours cancellation, and never
	// reports Complete on a failed page.
	Collect(ctx context.Context, sink Sink) error
}

// Budget bounds the total provider API calls a scan may make, so a scan's cost
// is predictable. A collector spends from it before each call and records
// Partial when it is exhausted, never truncating silently. It is safe for
// concurrent use.
type Budget struct {
	mu        sync.Mutex
	remaining int64
}

// NewBudget returns a budget of n calls.
func NewBudget(n int64) *Budget { return &Budget{remaining: n} }

// Spend consumes one call from the budget. It returns false when the budget is
// exhausted, which a collector must treat as Partial, not as an end of data. A
// nil Budget is unlimited: every Spend succeeds, so "no --budget" threads a nil
// budget and every collector's spend call is a no-op.
func (b *Budget) Spend() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return false
	}
	b.remaining--
	return true
}

// Remaining reports the calls left. A nil (unlimited) Budget reports the maximum,
// so callers that display it never special-case nil.
func (b *Budget) Remaining() int64 {
	if b == nil {
		return math.MaxInt64
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining
}

// Run executes the collectors in order, emitting to sink, and stops promptly if
// the context is cancelled, returning what was gathered so far. A collector's
// error is recorded and does not stop the others: one collector failing must
// never silently drop the rest, and the completeness records show the gap.
func Run(ctx context.Context, collectors []Collector, sink Sink) error {
	var errs []error
	for _, c := range collectors {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := c.Collect(ctx, sink); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.ID(), err))
		}
	}
	return errors.Join(errs...)
}
