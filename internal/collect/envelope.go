// Package collect is the provider-neutral collection framework (ADR-0018). It
// defines what a collector is, the evidence envelope and completeness records a
// collection produces, the budget and orchestration that bound a run, and the
// read-only enforcement that keeps a collector from ever calling a write,
// secret-value, or object-content operation.
//
// It imports no cloud SDK: the provider-specific collectors that call real APIs
// live in providers/<provider>, are built with their provider's authenticated
// read-only clients (from the credential the identity adapter already resolves),
// and emit the provider-neutral evidence and model rows this package defines.
package collect

import (
	"encoding/json"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Global is the region value for a service that is not regional.
const Global = "global"

// Scope names what a collection read, with no secret parameters.
type Scope struct {
	// Account is the account, subscription, or project the read was scoped to.
	Account string `json:"account,omitempty"`
	// Resource is the specific resource id, when the read was resource-scoped.
	Resource string `json:"resource,omitempty"`
}

// Provenance ties an envelope to the exact call that produced it, so evidence is
// reproducible and auditable.
type Provenance struct {
	APIVersion string `json:"api_version"`
	Collector  string `json:"collector"`
}

// Envelope is the redacted, secret-free record of one read (ADR-0018 §2). The
// Response is the provider's response with secret values and object contents
// removed; it is never stored raw.
type Envelope struct {
	Provider    model.Provider  `json:"provider"`
	Service     string          `json:"service"`
	Operation   string          `json:"operation"`
	Region      string          `json:"region"`
	CollectedAt time.Time       `json:"collected_at"`
	Scope       Scope           `json:"scope"`
	Response    json.RawMessage `json:"response"`
	Provenance  Provenance      `json:"provenance"`
}

// Status is the completeness of one (service, region, scope) enumeration. A
// status is never Complete when a page failed, a call was denied, or the budget
// was exhausted (ADR-0018 §2): an unknown is never turned into "nothing found".
type Status string

const (
	// Complete means the enumeration finished and every page was read.
	Complete Status = "complete"
	// Partial means some resources were read and others were not (throttled,
	// timed out, a page failed, or the budget ran out).
	Partial Status = "partial"
	// Denied means the API returned access-denied.
	Denied Status = "denied"
	// Unsupported means the service or region is not offered for this account.
	Unsupported Status = "unsupported"
	// Errored means an unexpected failure prevented the read.
	Errored Status = "error"
)

// Completeness reports how fully one enumeration finished. Reason is required
// whenever Status is not Complete, so a gap is always explained.
type Completeness struct {
	Service   string `json:"service"`
	Region    string `json:"region"`
	Scope     Scope  `json:"scope"`
	Status    Status `json:"status"`
	Collected int    `json:"collected"`
	Reason    string `json:"reason,omitempty"`
}

// Done reports whether the enumeration accounted for everything in scope. Only
// Complete is done; every other status leaves a gap a rule or report must see.
func (c Completeness) Done() bool { return c.Status == Complete }
