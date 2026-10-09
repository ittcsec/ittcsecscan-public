package report

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

// The ITTCsecID section surfaces the effective-privilege resolution faithfully: grants
// are present and sorted, deny-override semantics are preserved (a capped grant shows
// effect "deny", not dropped), the resolution's completeness is carried, and dormant
// privilege is the honest named gap, never a fabricated value.
func TestIdentitySectionBuildsFaithfully(t *testing.T) {
	in := Input{
		Tenant: "tenant-1", ToolVersion: "test",
		IdentityComplete: false,
		IdentityGaps:     []string{"iam.policies denied"},
		IdentityGrants: []model.Permission{
			{Principal: "arn:aws:iam::1:role/zeta", Action: "admin", Effect: model.EffectAllow},
			{Principal: "arn:aws:iam::1:role/alpha", Action: "admin", Effect: model.EffectDeny, InheritedFrom: "arn:aws:iam::1:policy/boundary"},
		},
	}
	r := Build(in)

	if len(r.Identity.Grants) != 2 {
		t.Fatalf("grants = %d, want 2", len(r.Identity.Grants))
	}
	// Sorted by principal: alpha before zeta.
	if r.Identity.Grants[0].Principal != "arn:aws:iam::1:role/alpha" {
		t.Errorf("grants not sorted by principal: got %q first", r.Identity.Grants[0].Principal)
	}
	if r.Identity.Complete {
		t.Error("Complete should carry through as false")
	}
	if r.Identity.DormantStatus != DormantGapStatus {
		t.Errorf("dormant status = %q, want the named-gap constant", r.Identity.DormantStatus)
	}
	// Deny-override is surfaced, not silently dropped.
	var sawDeny, sawInherited bool
	for _, g := range r.Identity.Grants {
		if g.Effect == string(model.EffectDeny) {
			sawDeny = true
			for _, v := range g.Via {
				if strings.Contains(v, "inherited from") {
					sawInherited = true
				}
			}
		}
	}
	if !sawDeny {
		t.Error("deny effect was not surfaced in the ITTCsecID section")
	}
	if !sawInherited {
		t.Error("inherited-from provenance was not surfaced for the capped grant")
	}
}

// The section renders in the shared text lines (so HTML/PDF/DOCX carry it), including the
// heading, a grant with its effect, and the explicit dormant-privilege gap.
func TestIdentitySectionRenders(t *testing.T) {
	r := Build(Input{
		Tenant: "t", ToolVersion: "v", IdentityComplete: true,
		IdentityGrants: []model.Permission{{Principal: "p", Action: "admin", Effect: model.EffectDeny}},
	})
	var sb strings.Builder
	for _, ln := range reportLines(r) {
		sb.WriteString(ln.Text)
		sb.WriteString("\n")
	}
	out := sb.String()
	for _, want := range []string{"Effective access (ITTCsecID)", "[deny]", "dormant privilege:"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report is missing %q", want)
		}
	}
}

// The built report, with the identity section populated, still validates against the
// pinned report schema (the section was added additively under schema v1).
func TestReportWithIdentityValidatesSchema(t *testing.T) {
	r := Build(Input{
		Tenant: "t", ToolVersion: "v", IdentityComplete: true,
		IdentityGrants: []model.Permission{{Principal: "p", Action: "admin", Effect: model.EffectAllow}},
	})
	out, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateJSON(schema.ModelReport, out); err != nil {
		t.Fatalf("report with identity section violates the schema: %v\n%s", err, out)
	}
}
