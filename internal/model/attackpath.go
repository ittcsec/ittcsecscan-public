package model

// PathStep is one hop of an attack path: the entity reached, the kind of edge
// traversed to reach it, and the MITRE technique it represents. Steps are
// ordered by their position in AttackPath.Steps. Edges are named by endpoints
// and kind, never by the store's file-local edge ID.
type PathStep struct {
	Node      StableID `json:"node"`
	Via       EdgeKind `json:"via"`
	Technique string   `json:"technique,omitempty"`
}

// AttackPath is a route from an entry entity to a target entity, with a score,
// a confidence, and its ordered steps. The first step's Node is the entry.
type AttackPath struct {
	SchemaVersion int        `json:"schema_version"`
	Entry         StableID   `json:"entry"`
	Target        StableID   `json:"target"`
	Score         int        `json:"score"`
	Confidence    Confidence `json:"confidence"`
	Steps         []PathStep `json:"steps"`
}

// CutChange is one edge a cut set proposes to remove, by its endpoints and
// kind, with a human description of the change.
type CutChange struct {
	Source      StableID `json:"source"`
	Target      StableID `json:"target"`
	Kind        EdgeKind `json:"kind"`
	Description string   `json:"description"`
}

// CutSet is a candidate set of changes that removes attack paths, ranked by
// weighted path risk eliminated against total change cost (the attack-path design).
type CutSet struct {
	SchemaVersion int         `json:"schema_version"`
	Changes       []CutChange `json:"changes"`
	PathsRemoved  int         `json:"paths_removed"`
	RiskReduction int         `json:"risk_reduction"`
	Effort        int         `json:"effort"`
	Disruption    int         `json:"disruption"`
}

// RemediationPlan and RemediationAction live in remediation.go.
