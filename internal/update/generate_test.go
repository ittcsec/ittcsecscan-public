package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// TestGenerateProducesAVerifiableMetadataSet is the round-trip proof for UP-1: metadata
// built by Generate, signed with in-memory keys, is accepted by the same client
// (NewClient + VerifyChain + VerifyTarget) that a real update goes through. This proves the
// generator matches the verifier without needing the maintainer's offline keys.
func TestGenerateProducesAVerifiableMetadataSet(t *testing.T) {
	// One key per role.
	roles := []string{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp}
	priv := map[string]ed25519.PrivateKey{}
	roleKeys := map[string]GenKey{}
	for _, r := range roles {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv[r] = pk
		roleKeys[r] = GenKey{Public: authorizedLine(pub), KeyID: keyID(pub)}
	}
	signers := map[string]Signer{}
	for _, r := range roles {
		pk := priv[r]
		signers[r] = func(signed []byte) (string, error) {
			sig, err := sshsig.Sign(pk, Namespace, "sha512", signed)
			return string(sig), err
		}
	}

	// A release artifact to list as a target.
	artifact := []byte("the ittcsecscan linux/amd64 binary bytes")
	cfg := GenConfig{
		Now: time.Now(),
		Targets: []GenTarget{{
			Name: "ittcsecscan_1.0.0_linux_amd64", Length: len(artifact), SHA256: hashHex(artifact),
			Component: "ittcsecscan", Version: "1.0.0", Channel: "stable",
		}},
		RoleKeys: roleKeys,
		Versions: map[string]int{RoleRoot: 1, RoleTargets: 1, RoleSnapshot: 1, RoleTimestamp: 1},
		Expiry: map[string]time.Duration{
			RoleRoot: 365 * 24 * time.Hour, RoleTargets: 30 * 24 * time.Hour,
			RoleSnapshot: 7 * 24 * time.Hour, RoleTimestamp: 24 * time.Hour,
		},
	}
	files, err := Generate(cfg, signers)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The client anchors to the generated root, then verifies the chain and the target.
	client, err := NewClient(files["root.json"], func() time.Time { return cfg.Now.Add(time.Minute) })
	if err != nil {
		t.Fatalf("NewClient rejected the generated root: %v", err)
	}
	f := repo{files: map[string][]byte{
		"timestamp.json": files["timestamp.json"],
		"snapshot.json":  files["snapshot.json"],
		"targets.json":   files["targets.json"],
	}}
	tgts, err := client.VerifyChain(f)
	if err != nil {
		t.Fatalf("VerifyChain rejected the generated metadata: %v", err)
	}
	if _, err := client.VerifyTarget(tgts, "ittcsecscan_1.0.0_linux_amd64", artifact); err != nil {
		t.Fatalf("VerifyTarget rejected the listed artifact: %v", err)
	}
	// A tampered artifact must be refused.
	if _, err := client.VerifyTarget(tgts, "ittcsecscan_1.0.0_linux_amd64", append(artifact, 'x')); err == nil {
		t.Fatal("VerifyTarget accepted a tampered artifact")
	}
}

// TestGenerateRejectsMissingRoleInputs proves the generator fails closed when a role's key
// or signer is absent, rather than emitting an unsigned or partial set.
func TestGenerateRejectsMissingRoleInputs(t *testing.T) {
	if _, err := Generate(GenConfig{RoleKeys: map[string]GenKey{}}, map[string]Signer{}); err == nil {
		t.Fatal("Generate accepted a config with no role keys")
	}
}
