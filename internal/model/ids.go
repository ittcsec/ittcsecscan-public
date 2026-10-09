// Package model defines the canonical, versioned, provider-neutral types
// shared by every domain: entities, edges, evidence, findings, attack paths,
// and the scan manifest (the canonical model; ADR-0014).
//
// The model is plaintext and storage-neutral. It knows nothing of encryption,
// of the store's file-local integer node IDs, or of SQL. Objects are keyed by
// StableID, the tenant-scoped identifier of ADR-0010 §2. The store
// (internal/store) alone maps a model value to its rows: it resolves stable
// IDs to node IDs, seals the encrypted columns (ADR-0011 §3, ADR-0013), and
// translates the enumerations below to integer codes. A test enforces that no
// exported model type ever exposes a node ID, a sealed blob, a key, or a keyed
// hash (ADR-0014 §4).
//
// Invariants:
//   - Every edge carries source evidence, conditions, deny evaluation,
//     freshness, confidence, and an explanation trace.
//   - Stable IDs are tenant-scoped; identifiers never correlate across tenants.
//   - Rule outcomes are pass, fail, unknown, error, or not-applicable. Unknown
//     and error are never converted to pass.
//   - New domains extend these contracts; they never introduce parallel models.
package model

import "regexp"

// SchemaVersion is the version of a canonical document, carried in the
// document and checked on read (schemas/README.md, ADR-0011 §2). Version 1 is
// the only version.
const SchemaVersion = 1

// StableID is the tenant-scoped identity of an object: the hex encoding of a
// per-tenant HMAC of a provider-native identifier (ADR-0010 §2). The same
// native identifier yields unrelated StableIDs in different tenants, so a
// StableID never correlates an object across tenants. It is not a node ID:
// the store's file-local integer keys never appear in the model.
type StableID string

var stableIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Valid reports whether s is a well-formed stable ID: 64 lowercase hex
// characters, the encoding of a 32-byte HMAC.
func (s StableID) Valid() bool { return stableIDPattern.MatchString(string(s)) }

// Confidence is a percentage from 0 to 100.
type Confidence int

// Valid reports whether c is in range.
func (c Confidence) Valid() bool { return c >= 0 && c <= 100 }
