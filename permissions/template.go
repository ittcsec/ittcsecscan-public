package permissions

import (
	"encoding/json"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// schemaVersion is the value every template's schema_version field carries.
const schemaVersion = "permissions.v1"

// Profile is a least-privilege credential profile (ADR-0005). It mirrors
// auth.Profile; the two are kept in step by a test so this package does not
// import the auth seam.
type Profile string

const (
	Discovery    Profile = "discovery"
	DeepEvidence Profile = "deep-evidence"
	Remediation  Profile = "remediation"
)

// Profiles lists every profile, in privilege order.
var Profiles = []Profile{Discovery, DeepEvidence, Remediation}

// Status is a template's or entry's verification status.
type Status string

const (
	// Unverified means the permission has not been proven against a real test
	// account. It is the default and is never trusted as narrowed.
	Unverified Status = "unverified"
	// Verified means live access-denied verification passed (ADR-0016 §3). It
	// must carry evidence (see Verification).
	Verified Status = "verified"
)

// Verification records whether a template or entry has been proven, and how. A
// verified status must carry a date and method, so nothing is trusted on the
// word "verified" alone; the schema and TestVerifiedTemplatesHaveEvidence both
// enforce it.
type Verification struct {
	Status Status `json:"status"`
	Date   string `json:"date,omitempty"`
	Method string `json:"method,omitempty"`
}

// Entry is one permission the profile grants and the collectors or rules that
// require it.
type Entry struct {
	Permission   string       `json:"permission"`
	EnabledBy    []string     `json:"enabled_by"`
	Verification Verification `json:"verification"`
}

// Template is the read-only permissions ittcsecscan requires for one provider
// under one profile.
type Template struct {
	SchemaVersion string         `json:"schema_version"`
	Provider      model.Provider `json:"provider"`
	Profile       Profile        `json:"profile"`
	Verification  Verification   `json:"verification"`
	Permissions   []Entry        `json:"permissions"`
}

// path is the embedded file path for a provider and profile.
func path(p model.Provider, prof Profile) string {
	return string(p) + "/" + string(prof) + ".json"
}

// Load returns the template for a provider and profile, validated against the
// schema. It also checks that the file's provider and profile match the ones
// requested, so a misfiled template cannot pass unnoticed.
func Load(p model.Provider, prof Profile) (Template, error) {
	data, err := FS.ReadFile(path(p, prof))
	if err != nil {
		return Template{}, fmt.Errorf("no permission template for %s/%s: %w", p, prof, err)
	}
	if err := schema.ValidateJSON(schema.PermissionsTemplate, data); err != nil {
		return Template{}, fmt.Errorf("permission template %s/%s: %w", p, prof, err)
	}
	var t Template
	if err := json.Unmarshal(data, &t); err != nil {
		return Template{}, fmt.Errorf("permission template %s/%s: %w", p, prof, err)
	}
	if t.Provider != p || t.Profile != prof {
		return Template{}, fmt.Errorf("permission template %s/%s declares %s/%s", p, prof, t.Provider, t.Profile)
	}
	return t, nil
}

// All returns every template, one per provider per profile, validated.
func All() ([]Template, error) {
	out := make([]Template, 0, len(model.Providers)*len(Profiles))
	for _, p := range model.Providers {
		for _, prof := range Profiles {
			t, err := Load(p, prof)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
	}
	return out, nil
}
