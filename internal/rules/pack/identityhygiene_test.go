package pack

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

// The identity-hygiene pack is now embedded in packs.FS and signed by the offline pack key
// (like ai-guard); that it ships signed and verifies is covered by
// TestEmbeddedPacksAreSignedAndVerify. These tests independently load the real committed
// files out-of-band with an in-process key (pack.Load), proving the rules parse, verify,
// their digests match, validate, and evaluate honestly.

const idhDir = "../../../packs/identity-hygiene"

// loadIdentityHygiene loads the committed identity-hygiene pack via pack.Load.
func loadIdentityHygiene(t *testing.T) []rules.Rule {
	t.Helper()
	manifest := mustRead(t, idhDir+"/manifest.json")
	fsys := fstest.MapFS{"identity-hygiene/manifest.json": &fstest.MapFile{Data: manifest}}
	entries, err := os.ReadDir(idhDir + "/rules")
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		fsys["identity-hygiene/rules/"+e.Name()] = &fstest.MapFile{Data: mustRead(t, filepath.Join(idhDir, "rules", e.Name()))}
	}
	priv, pub := genKey(t)
	fsys["identity-hygiene/manifest.json.sig"] = &fstest.MapFile{Data: signArmored(t, priv, PackNamespace, "sha512", manifest)}
	pk, err := Load([]ed25519.PublicKey{pub}, fsys, "identity-hygiene")
	if err != nil {
		t.Fatalf("identity-hygiene pack did not load: %v", err)
	}
	return pk.Rules
}

// TestIdentityHygienePackLoads proves the committed pack parses, verifies, its digests
// match, and all ten rules validate (node types, operators, comparators, facts real).
func TestIdentityHygienePackLoads(t *testing.T) {
	rs := loadIdentityHygiene(t)
	want := map[string]bool{
		"IDH-AWS-IAM-USER-NO-MFA": false, "IDH-AWS-IAM-KEY-UNUSED": false, "IDH-AWS-IAM-KEY-UNROTATED": false,
		"IDH-AWS-ROOT-KEY-ACTIVE": false, "IDH-AWS-ROOT-NO-MFA": false, "IDH-AWS-ROLE-DORMANT": false,
		"IDH-AZURE-APP-CRED-EXPIRED": false, "IDH-AZURE-APP-CRED-LONG-LIFETIME": false,
		"IDH-AZURE-APP-HIGH-PRIV-GRANT": false, "IDH-GCP-SA-KEY-OLD": false,
	}
	for _, r := range rs {
		if _, ok := want[r.ID]; !ok {
			t.Errorf("unexpected rule %q", r.ID)
		}
		want[r.ID] = true
		if r.PackID != "identity-hygiene" {
			t.Errorf("rule %s pack id = %q", r.ID, r.PackID)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("rule %s invalid: %v", r.ID, err)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("rule %s missing from the pack", id)
		}
	}
}

// TestIdentityHygieneEvaluates proves two representative rules behave honestly on a
// Complete scan: the GCP old-key rule fails an old key, passes a fresh one, and reports
// Unknown (never pass) for a key whose age is a non-numeric sentinel; the Azure
// high-impact rule fires only for a Microsoft Graph grant in the allowlist and reports
// Unknown for an unresolved grant.
func TestIdentityHygieneEvaluates(t *testing.T) {
	rs := loadIdentityHygiene(t)
	var gcp, azure rules.Rule
	for _, r := range rs {
		switch r.ID {
		case "IDH-GCP-SA-KEY-OLD":
			gcp = r
		case "IDH-AZURE-APP-HIGH-PRIV-GRANT":
			azure = r
		}
	}

	scan := &collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeCredential, NativeID: "k-old", Attributes: map[string]string{"key_type": "user_managed", "key_age_days": "412"}},
			{Type: model.NodeCredential, NativeID: "k-new", Attributes: map[string]string{"key_type": "user_managed", "key_age_days": "10"}},
			{Type: model.NodeCredential, NativeID: "k-bad", Attributes: map[string]string{"key_type": "user_managed", "key_age_days": "N/A"}},
		},
		Completeness: []collect.Completeness{{Service: "iam.serviceAccountKeys", Region: collect.Global, Status: collect.Complete}},
	}
	rsg, err := rules.Evaluate(nrm(scan), []rules.Rule{gcp})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]model.Outcome{"k-old": model.Fail, "k-new": model.Pass, "k-bad": model.OutcomeUnknown} {
		if got := idhStateFor(rsg, id); got != want {
			t.Errorf("gcp key %s = %s, want %s", id, got, want)
		}
	}

	graph := "00000003-0000-0000-c000-000000000000"
	ascan := &collect.Scan{
		Nodes: []collect.Node{
			{Type: model.NodeRole, NativeID: "g/high", Attributes: map[string]string{"grant_type": "application", "resource_app_id": graph, "resolved": "true", "permission": "RoleManagement.ReadWrite.Directory"}},
			{Type: model.NodeRole, NativeID: "g/low", Attributes: map[string]string{"grant_type": "application", "resource_app_id": graph, "resolved": "true", "permission": "User.Read.All"}},
			{Type: model.NodeRole, NativeID: "g/unres", Attributes: map[string]string{"grant_type": "application", "resource_app_id": graph, "resolved": "false", "permission": ""}},
			{Type: model.NodeRole, NativeID: "other/high", Attributes: map[string]string{"grant_type": "application", "resource_app_id": "other-app", "resolved": "true", "permission": "RoleManagement.ReadWrite.Directory"}},
		},
		Completeness: []collect.Completeness{{Service: "entra.appRoleAssignments", Region: collect.Global, Status: collect.Complete}},
	}
	rsa, err := rules.Evaluate(nrm(ascan), []rules.Rule{azure})
	if err != nil {
		t.Fatal(err)
	}
	if got := idhStateFor(rsa, "g/high"); got != model.Fail {
		t.Errorf("high-priv Graph grant = %s, want fail", got)
	}
	if got := idhStateFor(rsa, "g/low"); got != model.Pass {
		t.Errorf("low Graph grant = %s, want pass", got)
	}
	if got := idhStateFor(rsa, "g/unres"); got != model.OutcomeUnknown {
		t.Errorf("unresolved grant = %s, want unknown (never pass)", got)
	}
	// A non-Graph resource app is not selected at all (no result).
	if got := idhStateFor(rsa, "other/high"); got != "" {
		t.Errorf("non-Graph grant = %s, want not selected", got)
	}
}

func idhStateFor(rs []rules.Result, entity string) model.Outcome {
	for _, r := range rs {
		if r.EntityID == entity {
			return r.State
		}
	}
	return ""
}
