package collect

import "github.com/ittcsec/ittcsecscan/internal/model"

// A collector emits the graph it finds keyed by provider-native identifiers. It
// does not know the tenant-stable ids or the sealed storage form: the store
// computes the stable id from the native id and seals fields at ingest
// (ADR-0010, ADR-0014). Node and Link are therefore the collected, pre-storage
// shape, not model.Entity and model.Edge, which are the stored and read form.

// Node is an entity a collector found.
type Node struct {
	Type       model.NodeType
	NativeID   string // the provider-native id (an ARN, a resource id)
	Name       string
	Attributes map[string]string
}

// Link is a relationship a collector found, between two native ids. Conditions
// carries any qualifiers on the relationship (for example a conditional IAM role
// binding's CEL expression), so an edge that applies only under a condition is
// not recorded as an unconditional one.
type Link struct {
	SourceNativeID string
	TargetNativeID string
	Kind           model.EdgeKind
	Conditions     map[string]string
}

// Scan is an accumulating Sink: a collector emits into it, and the accumulated
// nodes, links, evidence, and completeness are then ingested through the store
// in one transaction (ADR-0018 §3). Holding the whole scan keeps the collector
// ignorant of the store's transactions, tenant files, and keys, and preserves
// the all-or-nothing ingest discipline every other write path in the store has.
type Scan struct {
	Nodes        []Node
	Links        []Link
	Envelopes    []Envelope
	Completeness []Completeness
}

// Node records a collected entity.
func (s *Scan) Node(n Node) error { s.Nodes = append(s.Nodes, n); return nil }

// Link records a collected relationship.
func (s *Scan) Link(l Link) error { s.Links = append(s.Links, l); return nil }

// Evidence records an evidence envelope.
func (s *Scan) Evidence(e Envelope) error { s.Envelopes = append(s.Envelopes, e); return nil }

// Complete records a completeness result.
func (s *Scan) Complete(c Completeness) error { s.Completeness = append(s.Completeness, c); return nil }

// Complete reports whether every completeness record in the scan is Complete:
// the scan accounted for everything in scope, with no partial, denied, or errored
// enumeration.
func (s *Scan) Full() bool {
	for _, c := range s.Completeness {
		if !c.Done() {
			return false
		}
	}
	return len(s.Completeness) > 0
}
