package model

import "time"

// Evidence is one observation that supports a fact: which collector saw it,
// through which provider API, when, and the redacted value. Secret values are
// never stored (a safety invariant); Value is already redacted. The store
// records a keyed hash of the value for change detection; that hash is not part
// of the model.
type Evidence struct {
	SchemaVersion int          `json:"schema_version"`
	Collector     string       `json:"collector"`
	API           string       `json:"api"`
	ObservedAt    time.Time    `json:"observed_at"`
	Value         string       `json:"value"`
	Freshness     Freshness    `json:"freshness"`
	Completeness  Completeness `json:"completeness"`
}

// Scope is one account, subscription, or project that a scan covered, with how
// many objects were requested and observed and whether the enumeration was
// complete.
type Scope struct {
	Provider     Provider     `json:"provider"`
	Account      string       `json:"account"`
	Region       string       `json:"region,omitempty"`
	Requested    int          `json:"requested"`
	Observed     int          `json:"observed"`
	Completeness Completeness `json:"completeness"`
}

// ScanManifest describes one scan: the tool version, when it ran, its status,
// and the scopes it covered. An interrupted scan is Incomplete, never
// Completed (threat T-19). CompletedAt is nil until the scan finishes.
type ScanManifest struct {
	SchemaVersion int        `json:"schema_version"`
	ToolVersion   string     `json:"tool_version"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Status        ScanStatus `json:"status"`
	Scopes        []Scope    `json:"scopes"`
}
