// Package repo is the storage-neutral boundary between the engine and the
// per-tenant store (ADR-0014). It holds the repository interfaces and the
// transaction handles the engine reads and writes through, in terms of the
// canonical types of internal/model. It imports only internal/model, context,
// and the standard library's errors for one sentinel: no SQL, no encryption,
// no store types. The store (internal/store) implements these interfaces and
// alone knows about node IDs, sealing, and the schema.
//
// Repositories are never free-standing: they are handed out inside a
// transaction closure (store's Tenant.View and Tenant.Update), so every
// repository reached from one closure shares that closure's single
// transaction. A scan ingest is therefore one atomic Update.
package repo

import (
	"context"
	"errors"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// ErrNotFound reports that a requested object does not exist in the tenant.
var ErrNotFound = errors.New("repo: object not found")

// Reader is the read side of one consistent tenant snapshot, obtained inside
// Tenant.View. Every repository it returns reads that one snapshot.
type Reader interface {
	Settings() SettingsReader
	Entities() EntityReader
}

// Writer is the read-write side of one transaction, obtained inside
// Tenant.Update. Every repository it returns shares the transaction, which
// commits as a unit when the closure returns nil and rolls back otherwise.
type Writer interface {
	Settings() SettingsWriter
	// Entities reads are available inside an update; entity writes are
	// scan-scoped and arrive with the ingest work.
	Entities() EntityReader
}

// Settings is a tenant's operator-controlled settings.
type Settings struct {
	// RetentionScans is how many recent completed scans to keep (1..30,
	// ADR-0011 §1).
	RetentionScans int
	// DisplayName is the operator's label for the tenant; it is encrypted at
	// rest (ADR-0011 §3).
	DisplayName string
}

// SettingsReader reads a tenant's settings.
type SettingsReader interface {
	Get(ctx context.Context) (Settings, error)
}

// SettingsWriter reads and changes a tenant's settings.
type SettingsWriter interface {
	SettingsReader
	SetRetentionScans(ctx context.Context, n int) error
	SetDisplayName(ctx context.Context, name string) error
}

// EntityReader reads entities by their stable ID.
type EntityReader interface {
	// Get returns the entity with the given stable ID, or ErrNotFound.
	Get(ctx context.Context, id model.StableID) (model.Entity, error)
}

// StableIDer derives the tenant-scoped stable ID of a provider-native id: the
// per-tenant HMAC of ADR-0010 §2. The store owns the key and implements this;
// the normalizer (ADR-0023) borrows the derivation from an open tenant, the
// same way repositories are obtained, so it can key the canonical model graph
// without the analysis side ever holding the key (ADR-0014 §4). Keying is a
// pure local computation, so it takes no context.
type StableIDer interface {
	StableID(nativeID string) (model.StableID, error)
}
