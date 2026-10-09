package pack

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/rules"
)

func sampleRuleJSON() []byte {
	r := rules.Rule{
		ID: "PACK-TEST-1", Version: "1", Title: "public storage",
		Severity:   model.SeverityHigh,
		Selector:   rules.Selector{NodeType: model.NodeDataStore},
		Predicate:  rules.Predicate{Op: rules.OpFactPresent, Fact: "iam_all_users_roles"},
		Requires:   rules.Requirements{Completeness: []string{"storage.bucketIam"}},
		Confidence: rules.ConfidenceModel{Base: 90},
	}
	b, _ := json.Marshal(r)
	return b
}

// buildPack assembles a signed pack in an in-memory FS. digestOverride, when non-empty,
// replaces the rule digest in the manifest (to simulate tampering).
func buildPack(t *testing.T, priv ed25519.PrivateKey, ruleBytes []byte, digestOverride string) fstest.MapFS {
	t.Helper()
	sum := sha256.Sum256(ruleBytes)
	digest := hex.EncodeToString(sum[:])
	if digestOverride != "" {
		digest = digestOverride
	}
	m := Manifest{
		SchemaVersion: 1, PackID: "test-pack", Version: "1.0.0",
		EngineMin: 1, EngineMax: 1,
		Providers: []model.Provider{model.AWS},
		Domains:   []string{"object storage"},
		Rules:     []RuleEntry{{ID: "PACK-TEST-1", File: "rules/r1.json", Digest: digest}},
	}
	manifestBytes, _ := json.Marshal(m)
	sig := signArmored(t, priv, PackNamespace, "sha512", manifestBytes)
	return fstest.MapFS{
		"p/manifest.json":     {Data: manifestBytes},
		"p/manifest.json.sig": {Data: sig},
		"p/rules/r1.json":     {Data: ruleBytes},
	}
}

// TestLoadValidPack proves a well-formed, correctly signed pack loads with its validated
// rules.
func TestLoadValidPack(t *testing.T) {
	priv, pub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	pk, err := Load([]ed25519.PublicKey{pub}, fsys, "p")
	if err != nil {
		t.Fatalf("valid pack did not load: %v", err)
	}
	if pk.Manifest.PackID != "test-pack" || len(pk.Rules) != 1 || pk.Rules[0].ID != "PACK-TEST-1" {
		t.Errorf("loaded pack = %+v", pk)
	}
	if pk.Rules[0].PackID != "test-pack" {
		t.Error("rule was not stamped with its pack id")
	}
}

// TestLoadRejectsTamperedRule proves a rule whose bytes no longer match the signed
// manifest digest is refused (the signature covers the manifest, the manifest pins the
// rule).
func TestLoadRejectsTamperedRule(t *testing.T) {
	priv, pub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	// Tamper the rule file after signing, leaving the manifest (and its digest) intact.
	tampered := append([]byte(nil), sampleRuleJSON()...)
	tampered = []byte(strings.Replace(string(tampered), "iam_all_users_roles", "harmless_fact", 1))
	fsys["p/rules/r1.json"] = &fstest.MapFile{Data: tampered}
	if _, err := Load([]ed25519.PublicKey{pub}, fsys, "p"); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("tampered rule: err = %v, want a digest mismatch", err)
	}
}

// TestLoadRejectsBadSignature proves an untrusted signer is refused before any rule is
// read.
func TestLoadRejectsBadSignature(t *testing.T) {
	priv, _ := genKey(t)
	_, otherPub := genKey(t)
	fsys := buildPack(t, priv, sampleRuleJSON(), "")
	if _, err := Load([]ed25519.PublicKey{otherPub}, fsys, "p"); err == nil {
		t.Error("pack signed by an untrusted key loaded")
	}
}

// TestLoadRejectsEngineIncompatible proves a pack whose engine range excludes this build
// is refused.
func TestLoadRejectsEngineIncompatible(t *testing.T) {
	priv, pub := genKey(t)
	ruleBytes := sampleRuleJSON()
	sum := sha256.Sum256(ruleBytes)
	m := Manifest{
		SchemaVersion: 1, PackID: "future-pack", Version: "1.0.0",
		EngineMin: 99, EngineMax: 99,
		Rules: []RuleEntry{{ID: "PACK-TEST-1", File: "rules/r1.json", Digest: hex.EncodeToString(sum[:])}},
	}
	mb, _ := json.Marshal(m)
	sig := signArmored(t, priv, PackNamespace, "sha512", mb)
	fsys := fstest.MapFS{
		"p/manifest.json":     {Data: mb},
		"p/manifest.json.sig": {Data: sig},
		"p/rules/r1.json":     {Data: ruleBytes},
	}
	if _, err := Load([]ed25519.PublicKey{pub}, fsys, "p"); err == nil || !strings.Contains(err.Error(), "engine") {
		t.Errorf("engine-incompatible pack: err = %v, want an engine range error", err)
	}
}

// TestLoadRejectsInvalidRule proves a syntactically valid but semantically invalid rule
// (no completeness contract) is refused at load, not silently at evaluation.
func TestLoadRejectsInvalidRule(t *testing.T) {
	priv, pub := genKey(t)
	bad := rules.Rule{ID: "BAD", Version: "1", Severity: model.SeverityHigh, Selector: rules.Selector{NodeType: model.NodeDataStore},
		Predicate: rules.Predicate{Op: rules.OpFactPresent, Fact: "x"}}
	bb, _ := json.Marshal(bad)
	fsys := buildPack(t, priv, bb, "")
	if _, err := Load([]ed25519.PublicKey{pub}, fsys, "p"); err == nil {
		t.Error("a rule with no completeness contract loaded")
	}
}
