package permissions

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// TestAllTemplatesLoadAndValidate proves every shipped template exists, matches
// the schema, and is filed under the provider and profile it declares.
func TestAllTemplatesLoadAndValidate(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("loading templates: %v", err)
	}
	if want := len(model.Providers) * len(Profiles); len(all) != want {
		t.Fatalf("loaded %d templates, want %d", len(all), want)
	}
	for _, tpl := range all {
		if tpl.SchemaVersion != schemaVersion {
			t.Errorf("%s/%s: schema_version %q", tpl.Provider, tpl.Profile, tpl.SchemaVersion)
		}
	}
}

// TestProfilesMatchAuthProfiles keeps this package's profile vocabulary in step
// with the auth seam without importing it in non-test code.
func TestProfilesMatchAuthProfiles(t *testing.T) {
	if len(Profiles) != len(auth.Profiles) {
		t.Fatalf("profile count: permissions %d, auth %d", len(Profiles), len(auth.Profiles))
	}
	for i, p := range Profiles {
		if string(p) != string(auth.Profiles[i]) {
			t.Errorf("profile %d: permissions %q, auth %q", i, p, auth.Profiles[i])
		}
	}
}

// The whole-repo reconciliation of the shipped templates against every
// collector's declared requirements lives in package providers, which links all
// the collectors; this package cannot import them without a cycle. See
// providers.TestTemplatesReconcileWithCollectors.

// TestReconcileCatchesBothDirections proves the reconciliation is adversarial:
// neither an undeclared nor an invented permission can pass.
func TestReconcileCatchesBothDirections(t *testing.T) {
	tmpl := func(perms ...Entry) []Template {
		return []Template{{Provider: model.AWS, Profile: Discovery, Permissions: perms}}
	}
	entry := Entry{Permission: "ec2:DescribeInstances", EnabledBy: []string{"collector:aws.ec2"}}
	req := Requirement{Provider: model.AWS, Profile: Discovery, Permission: "ec2:DescribeInstances", By: "collector:aws.ec2"}

	// Matching template and requirement reconcile.
	if err := Reconcile(tmpl(entry), []Requirement{req}); err != nil {
		t.Fatalf("matching pair should reconcile: %v", err)
	}
	// A requirement with no template entry: undeclared-but-needed.
	if err := Reconcile(tmpl(), []Requirement{req}); err == nil {
		t.Error("a required permission missing from the template was not caught")
	}
	// A template entry no requirement backs: invented permission.
	if err := Reconcile(tmpl(entry), nil); err == nil {
		t.Error("an invented (unrequired) template permission was not caught")
	}
	// The right permission credited to the wrong collector is still a mismatch.
	wrong := Requirement{Provider: model.AWS, Profile: Discovery, Permission: "ec2:DescribeInstances", By: "collector:other"}
	if err := Reconcile(tmpl(entry), []Requirement{wrong}); err == nil {
		t.Error("a permission credited to the wrong collector was not caught")
	}
	// Empty and empty reconcile: the state.
	if err := Reconcile(nil, nil); err != nil {
		t.Errorf("empty state should reconcile: %v", err)
	}
}

// TestSchemaRejectsVerifiedWithoutEvidence proves the verification-honesty gate:
// a template (or entry) cannot claim "verified" without a date and method, so
// nothing is trusted as narrowed on the word alone.
func TestSchemaRejectsVerifiedWithoutEvidence(t *testing.T) {
	bad := []byte(`{
	  "schema_version": "permissions.v1",
	  "provider": "aws",
	  "profile": "discovery",
	  "verification": { "status": "verified" },
	  "permissions": []
	}`)
	if err := schema.ValidateJSON(schema.PermissionsTemplate, bad); err == nil {
		t.Fatal("a verified template with no date or method was accepted")
	}

	good := []byte(`{
	  "schema_version": "permissions.v1",
	  "provider": "aws",
	  "profile": "discovery",
	  "verification": { "status": "verified", "date": "2026-09-18T00:00:00Z", "method": "TestLive..." },
	  "permissions": []
	}`)
	if err := schema.ValidateJSON(schema.PermissionsTemplate, good); err != nil {
		t.Fatalf("a verified template with evidence was rejected: %v", err)
	}
}

// TestSchemaRejectsUnjustifiedPermission proves a permission must name at least
// one collector or rule that enables it: a permission with no justification is
// not least-privilege.
func TestSchemaRejectsUnjustifiedPermission(t *testing.T) {
	bad := []byte(`{
	  "schema_version": "permissions.v1",
	  "provider": "aws",
	  "profile": "discovery",
	  "verification": { "status": "unverified" },
	  "permissions": [ { "permission": "ec2:DescribeInstances", "enabled_by": [], "verification": { "status": "unverified" } } ]
	}`)
	if err := schema.ValidateJSON(schema.PermissionsTemplate, bad); err == nil {
		t.Fatal("a permission with an empty enabled_by was accepted")
	}
}

// TestExcess checks the report-only overbroad comparison.
func TestExcess(t *testing.T) {
	tpl := Template{Permissions: []Entry{
		{Permission: "ec2:DescribeInstances", EnabledBy: []string{"c"}},
		{Permission: "s3:ListAllMyBuckets", EnabledBy: []string{"c"}},
	}}
	granted := []string{"s3:ListAllMyBuckets", "ec2:DescribeInstances", "iam:CreateUser", "ec2:TerminateInstances", "iam:CreateUser"}
	got := Excess(granted, tpl)
	want := []string{"ec2:TerminateInstances", "iam:CreateUser"}
	if len(got) != len(want) {
		t.Fatalf("Excess = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Excess = %v, want %v", got, want)
		}
	}
	// Against an empty template every grant is excess: the reason overbroad
	// detection stays report-only until a template is populated.
	if e := Excess([]string{"a", "b"}, Template{}); len(e) != 2 {
		t.Errorf("empty template: Excess = %v, want both", e)
	}
}
