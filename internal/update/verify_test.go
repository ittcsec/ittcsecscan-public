package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

var testNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testNow }

type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer{priv: priv, pub: pub}
}

func (s signer) id() string { return keyID(s.pub) }

// authorizedLine encodes an Ed25519 public key as an OpenSSH authorized-signers line.
func authorizedLine(pub ed25519.PublicKey) string {
	var b []byte
	appendStr := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s))) //nolint:gosec // G115: SSH string lengths are bounded by in-memory buffer sizes
		b = append(b, l[:]...)
		b = append(b, s...)
	}
	appendStr([]byte("ssh-ed25519"))
	appendStr(pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b)
}

func (s signer) key() Key { return Key{Type: "ssh-ed25519", Public: authorizedLine(s.pub)} }

func signMeta(t *testing.T, body any, signers ...signer) []byte {
	t.Helper()
	signed, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var sigs []Signature
	for _, s := range signers {
		armored, err := sshsig.Sign(s.priv, Namespace, "sha512", signed)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, Signature{KeyID: s.id(), Sig: string(armored)})
	}
	raw, err := json.Marshal(Metadata{Signed: signed, Signatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type repo struct{ files map[string][]byte }

func (r repo) Fetch(name string) ([]byte, error) {
	b, ok := r.files[name]
	if !ok {
		return nil, fmt.Errorf("not found: %s", name)
	}
	return b, nil
}

// fixture is a complete signed repo with one target, at a given version, with an
// injectable expiry, so tests can mutate individual pieces.
type fixture struct {
	root                   signer
	tsKey, snapKey, tgtKey signer
	rootRaw                []byte
	repo                   repo
	targetName             string
	targetData             []byte
}

func buildFixture(t *testing.T, version int, expires time.Time) fixture {
	t.Helper()
	f := fixture{
		root: newSigner(t), tsKey: newSigner(t), snapKey: newSigner(t), tgtKey: newSigner(t),
		targetName: "pack:core-p0", targetData: []byte("component payload v" + fmt.Sprint(version)),
	}
	hdr := func(typ string) header {
		return header{Spec: Spec, Type: typ, Version: version, Expires: expires}
	}
	targets := struct {
		header
		Targets map[string]Target `json:"targets"`
	}{hdr(RoleTargets), map[string]Target{
		f.targetName: {Length: len(f.targetData), SHA256: hashHex(f.targetData), Custom: TargetCustom{Component: "detection-pack", Version: "1.0.0", Channel: "stable"}},
	}}
	targetsRaw := signMeta(t, targets, f.tgtKey)

	snapshot := struct {
		header
		Meta map[string]MetaRef `json:"meta"`
	}{hdr(RoleSnapshot), map[string]MetaRef{
		"targets.json": {Version: version, Length: len(targetsRaw), SHA256: hashHex(targetsRaw)},
	}}
	snapshotRaw := signMeta(t, snapshot, f.snapKey)

	timestamp := struct {
		header
		Meta map[string]MetaRef `json:"meta"`
	}{hdr(RoleTimestamp), map[string]MetaRef{
		"snapshot.json": {Version: version, Length: len(snapshotRaw), SHA256: hashHex(snapshotRaw)},
	}}
	timestampRaw := signMeta(t, timestamp, f.tsKey)

	root := struct {
		header
		Keys  map[string]Key      `json:"keys"`
		Roles map[string]RoleKeys `json:"roles"`
	}{hdr(RoleRoot),
		map[string]Key{
			f.root.id(): f.root.key(), f.tsKey.id(): f.tsKey.key(),
			f.snapKey.id(): f.snapKey.key(), f.tgtKey.id(): f.tgtKey.key(),
		},
		map[string]RoleKeys{
			RoleRoot:      {KeyIDs: []string{f.root.id()}, Threshold: 1},
			RoleTimestamp: {KeyIDs: []string{f.tsKey.id()}, Threshold: 1},
			RoleSnapshot:  {KeyIDs: []string{f.snapKey.id()}, Threshold: 1},
			RoleTargets:   {KeyIDs: []string{f.tgtKey.id()}, Threshold: 1},
		},
	}
	f.rootRaw = signMeta(t, root, f.root)
	f.repo = repo{files: map[string][]byte{
		"timestamp.json": timestampRaw, "snapshot.json": snapshotRaw, "targets.json": targetsRaw,
	}}
	return f
}

func TestVerifyChainHappyPath(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	c, err := NewClient(f.rootRaw, fixedNow)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tgts, err := c.VerifyChain(f.repo)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	tgt, err := c.VerifyTarget(tgts, f.targetName, f.targetData)
	if err != nil {
		t.Fatalf("VerifyTarget: %v", err)
	}
	if tgt.Custom.Component != "detection-pack" {
		t.Errorf("unexpected component: %s", tgt.Custom.Component)
	}
}

// Untrusted-metadata rejection: timestamp signed by a key that is not the authorized
// timestamp key is refused.
func TestUntrustedKeyRejected(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	// Re-sign timestamp with an attacker key not listed for the timestamp role.
	attacker := newSigner(t)
	ts := struct {
		header
		Meta map[string]MetaRef `json:"meta"`
	}{header{Spec: Spec, Type: RoleTimestamp, Version: 1, Expires: testNow.Add(24 * time.Hour)},
		map[string]MetaRef{"snapshot.json": mustRef(t, f.repo.files["snapshot.json"], 1)}}
	f.repo.files["timestamp.json"] = signMeta(t, ts, attacker)

	c, _ := NewClient(f.rootRaw, fixedNow)
	if _, err := c.VerifyChain(f.repo); !errors.Is(err, ErrThreshold) {
		t.Fatalf("want ErrThreshold for untrusted signer, got %v", err)
	}
}

// Expired metadata is refused.
func TestExpiredRejected(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(-1*time.Hour)) // already expired
	c, err := NewClient(f.rootRaw, fixedNow)
	if err == nil {
		if _, err = c.VerifyChain(f.repo); err == nil {
			t.Fatal("expected expiry to be refused")
		}
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

// Rollback protection: after trusting version 5, a version-4 timestamp is refused.
func TestRollbackRejected(t *testing.T) {
	newer := buildFixture(t, 5, testNow.Add(24*time.Hour))
	c, err := NewClient(newer.rootRaw, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyChain(newer.repo); err != nil {
		t.Fatalf("verify newer: %v", err)
	}
	// Now serve an older, validly signed set (same keys) at version 4.
	older := rebuildAtVersion(t, newer, 4, testNow.Add(24*time.Hour))
	if _, err := c.VerifyChain(older.repo); !errors.Is(err, ErrRollback) {
		t.Fatalf("want ErrRollback for older version, got %v", err)
	}
}

// A tampered target (right name, wrong bytes) and an unknown target are refused.
func TestTargetIntegrity(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	c, _ := NewClient(f.rootRaw, fixedNow)
	tgts, err := c.VerifyChain(f.repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyTarget(tgts, f.targetName, append(f.targetData, 'X')); !errors.Is(err, ErrTarget) {
		t.Errorf("tampered target: want ErrTarget, got %v", err)
	}
	if _, err := c.VerifyTarget(tgts, "pack:does-not-exist", f.targetData); !errors.Is(err, ErrUnknownTarget) {
		t.Errorf("unknown target: want ErrUnknownTarget, got %v", err)
	}
}

// A snapshot whose bytes do not match the timestamp pin is refused before parsing.
func TestSnapshotPinMismatch(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	tampered := append([]byte{}, f.repo.files["snapshot.json"]...)
	tampered[len(tampered)-2] ^= 0x01
	f.repo.files["snapshot.json"] = tampered
	c, _ := NewClient(f.rootRaw, fixedNow)
	if _, err := c.VerifyChain(f.repo); !errors.Is(err, ErrTarget) {
		t.Fatalf("want ErrTarget for snapshot pin mismatch, got %v", err)
	}
}

// A root role threshold of 2 with only one signature fails closed at NewClient.
func TestRootThresholdEnforced(t *testing.T) {
	r1, r2 := newSigner(t), newSigner(t)
	root := struct {
		header
		Keys  map[string]Key      `json:"keys"`
		Roles map[string]RoleKeys `json:"roles"`
	}{header{Spec: Spec, Type: RoleRoot, Version: 1, Expires: testNow.Add(24 * time.Hour)},
		map[string]Key{r1.id(): r1.key(), r2.id(): r2.key()},
		map[string]RoleKeys{RoleRoot: {KeyIDs: []string{r1.id(), r2.id()}, Threshold: 2}},
	}
	oneSig := signMeta(t, root, r1) // only one of two required
	if _, err := NewClient(oneSig, fixedNow); !errors.Is(err, ErrThreshold) {
		t.Fatalf("want ErrThreshold for 1-of-2 root, got %v", err)
	}
	bothSig := signMeta(t, root, r1, r2)
	if _, err := NewClient(bothSig, fixedNow); err != nil {
		t.Fatalf("2-of-2 root should verify: %v", err)
	}
}

// Root rotation: a new root must be signed by both the old and the new root threshold.
func TestRootRotation(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	c, err := NewClient(f.rootRaw, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	newRootKey := newSigner(t)
	newRootBody := struct {
		header
		Keys  map[string]Key      `json:"keys"`
		Roles map[string]RoleKeys `json:"roles"`
	}{header{Spec: Spec, Type: RoleRoot, Version: 2, Expires: testNow.Add(48 * time.Hour)},
		map[string]Key{newRootKey.id(): newRootKey.key()},
		map[string]RoleKeys{
			RoleRoot:      {KeyIDs: []string{newRootKey.id()}, Threshold: 1},
			RoleTimestamp: {KeyIDs: []string{f.tsKey.id()}, Threshold: 1},
			RoleSnapshot:  {KeyIDs: []string{f.snapKey.id()}, Threshold: 1},
			RoleTargets:   {KeyIDs: []string{f.tgtKey.id()}, Threshold: 1},
		},
	}
	// keys map must also include the role keys so parseKeys can resolve them.
	nb := newRootBody
	nb.Keys[f.tsKey.id()] = f.tsKey.key()
	nb.Keys[f.snapKey.id()] = f.snapKey.key()
	nb.Keys[f.tgtKey.id()] = f.tgtKey.key()

	// Signed only by the NEW key: rejected (old root threshold not met).
	onlyNew := signMeta(t, nb, newRootKey)
	if err := c.UpdateRoot(onlyNew); err == nil {
		t.Fatal("rotation signed only by the new key must be rejected")
	}
	// Signed by BOTH old and new: accepted.
	both := signMeta(t, nb, f.root, newRootKey)
	if err := c.UpdateRoot(both); err != nil {
		t.Fatalf("valid rotation rejected: %v", err)
	}
}

// --- helpers for version rebuilds ---

func mustRef(t *testing.T, raw []byte, version int) MetaRef {
	t.Helper()
	return MetaRef{Version: version, Length: len(raw), SHA256: hashHex(raw)}
}

// rebuildAtVersion re-signs a fixture's chain at a new version using the SAME keys, so
// the signatures are valid but the versions differ (for rollback testing).
func rebuildAtVersion(t *testing.T, f fixture, version int, expires time.Time) fixture {
	t.Helper()
	hdr := func(typ string) header { return header{Spec: Spec, Type: typ, Version: version, Expires: expires} }
	targets := struct {
		header
		Targets map[string]Target `json:"targets"`
	}{hdr(RoleTargets), map[string]Target{
		f.targetName: {Length: len(f.targetData), SHA256: hashHex(f.targetData), Custom: TargetCustom{Component: "detection-pack", Version: "1.0.0", Channel: "stable"}},
	}}
	targetsRaw := signMeta(t, targets, f.tgtKey)
	snapshot := struct {
		header
		Meta map[string]MetaRef `json:"meta"`
	}{hdr(RoleSnapshot), map[string]MetaRef{"targets.json": mustRef(t, targetsRaw, version)}}
	snapshotRaw := signMeta(t, snapshot, f.snapKey)
	timestamp := struct {
		header
		Meta map[string]MetaRef `json:"meta"`
	}{hdr(RoleTimestamp), map[string]MetaRef{"snapshot.json": mustRef(t, snapshotRaw, version)}}
	timestampRaw := signMeta(t, timestamp, f.tsKey)
	out := f
	out.repo = repo{files: map[string][]byte{"timestamp.json": timestampRaw, "snapshot.json": snapshotRaw, "targets.json": targetsRaw}}
	return out
}
