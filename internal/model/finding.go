package model

import "time"

// RuleRef names the exact rule version a finding came from. Rules are public
// pack content (the canonical model), so these are not customer data.
type RuleRef struct {
	RuleID  string `json:"rule_id"`
	Version string `json:"version"`
	PackID  string `json:"pack_id"`
}

// Finding is the outcome of one rule against one entity. State is the rule
// outcome; Unknown and Error are never reported as Pass (a safety
// invariant). Status is the finding's lifecycle, whose vocabulary the
// detection engine defines (blocker B-5). Detail explains the result for a
// person.
type Finding struct {
	SchemaVersion int           `json:"schema_version"`
	Rule          RuleRef       `json:"rule"`
	Entity        StableID      `json:"entity"`
	State         Outcome       `json:"state"`
	Risk          int           `json:"risk"`
	Confidence    Confidence    `json:"confidence"`
	FirstSeen     time.Time     `json:"first_seen"`
	Status        FindingStatus `json:"status"`
	Detail        string        `json:"detail,omitempty"`
}
