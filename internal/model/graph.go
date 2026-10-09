package model

import "time"

// Entity is a node in the attack graph: an account, identity, resource, or any
// other §6 node type. It is keyed by its tenant-scoped StableID. NativeID,
// Name, Tags, and Attributes are the customer's own values, in plaintext here;
// the store seals them (ADR-0011 §3).
type Entity struct {
	SchemaVersion int               `json:"schema_version"`
	ID            StableID          `json:"id"`
	Provider      Provider          `json:"provider"`
	Type          NodeType          `json:"type"`
	NativeID      string            `json:"native_id"`
	Name          string            `json:"name,omitempty"`
	Criticality   int               `json:"criticality"`
	Tags          map[string]string `json:"tags,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
}

// Condition is one clause qualifying an edge or a permission, such as an IAM
// policy condition: a key, an operator, and the values it is tested against.
type Condition struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// Edge is a directed relationship between two entities, by their stable IDs.
// The design requires every edge to carry source evidence, conditions, a
// deny evaluation, freshness, confidence, and an explanation trace; those are
// first-class fields here, and an edge is never produced without them.
type Edge struct {
	SchemaVersion int         `json:"schema_version"`
	Source        StableID    `json:"source"`
	Target        StableID    `json:"target"`
	Kind          EdgeKind    `json:"kind"`
	Conditions    []Condition `json:"conditions,omitempty"`
	DenyEvaluated TriState    `json:"deny_evaluated"`
	Freshness     Freshness   `json:"freshness"`
	Confidence    Confidence  `json:"confidence"`
	Evidence      []Evidence  `json:"evidence"`
	Explanation   []string    `json:"explanation"`
}

// Permission is one effective grant: a principal may take an action on a
// resource, subject to a condition, possibly inherited from another entity.
// Effect's vocabulary (allow/deny) is deferred to the code that writes
// permissions (blocker B-5).
type Permission struct {
	SchemaVersion int         `json:"schema_version"`
	Principal     StableID    `json:"principal"`
	Resource      StableID    `json:"resource"`
	Action        string      `json:"action"`
	Effect        Effect      `json:"effect"`
	Condition     []Condition `json:"condition,omitempty"`
	InheritedFrom StableID    `json:"inherited_from,omitempty"`
}

// PortRange is a contiguous port range, both ends inclusive. A nil range means
// every port (ADR-0011: a range has both ends or neither).
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Exposure is effective reachability of an entity from a source zone. Protocol
// is an IANA protocol number, or nil for any protocol; Ports is nil for every
// port. Effective distinguishes configuration exposure (Unknown) from verified
// reachability. Zone's vocabulary is deferred (blocker B-5).
type Exposure struct {
	SchemaVersion int        `json:"schema_version"`
	Entity        StableID   `json:"entity"`
	Zone          Zone       `json:"zone"`
	Protocol      *int       `json:"protocol,omitempty"`
	Ports         *PortRange `json:"ports,omitempty"`
	AuthRequired  TriState   `json:"auth_required"`
	Effective     TriState   `json:"effective"`
	Trace         []string   `json:"trace"`
}

// Classification marks an entity as a sensitive asset: a label, the method
// that assigned it, a confidence, and an optional approved sample of the
// evidence a person confirmed.
type Classification struct {
	SchemaVersion  int        `json:"schema_version"`
	Entity         StableID   `json:"entity"`
	Label          string     `json:"label"`
	Method         string     `json:"method"`
	Confidence     Confidence `json:"confidence"`
	ApprovedSample string     `json:"approved_sample,omitempty"`
}

// CriticalityOverride is one audited human decision to set an asset's business
// criticality (ADR-0025 §4). It is a durable input, not a derived fact: it records
// who set it, when, and why. Overrides are append-only (the full history is kept);
// for a given entity the latest override is the effective one. At is for the audit
// trail; effective ordering is by the store's append order, so the classification
// engine, which is deterministic and clock-free, never reads a wall clock.
type CriticalityOverride struct {
	Entity      StableID  `json:"entity"`
	Criticality int       `json:"criticality"`
	Actor       string    `json:"actor"`
	Reason      string    `json:"reason,omitempty"`
	At          time.Time `json:"at"`
}
