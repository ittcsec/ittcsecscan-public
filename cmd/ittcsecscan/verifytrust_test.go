package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// pubLine renders an ed25519 public key as an "ssh-ed25519 <base64> comment" line.
func pubLine(pub ed25519.PublicKey) string {
	var blob []byte
	app := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s))) //nolint:gosec // G115: test-only helper; lengths are tiny constants
		blob = append(blob, l[:]...)
		blob = append(blob, s...)
	}
	app([]byte("ssh-ed25519"))
	app(pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " test\n"
}

// A good detached signature over the signed bytes, with the right key and namespace,
// verifies.
func TestVerifyDetachedGoodSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("SHA256SUMS content\n")
	sig, err := sshsig.Sign(priv, "ittcsecscan-release", "sha512", msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDetached(pubLine(pub), "ittcsecscan-release", msg, sig); err != nil {
		t.Fatalf("a good signature must verify: %v", err)
	}
}

// Fail-closed: every tamper must make verification fail. A mutation that let any of these
// through (reporting a bad signature as trusted) breaks this test.
func TestVerifyDetachedFailsClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("SHA256SUMS content\n")
	sig, err := sshsig.Sign(priv, "ittcsecscan-release", "sha512", msg)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"tampered message": func() error {
			return verifyDetached(pubLine(pub), "ittcsecscan-release", []byte("SHA256SUMS TAMPERED\n"), sig)
		},
		"wrong key":       func() error { return verifyDetached(pubLine(otherPub), "ittcsecscan-release", msg, sig) },
		"wrong namespace": func() error { return verifyDetached(pubLine(pub), "ittcsecscan-pack", msg, sig) },
		"malformed key":   func() error { return verifyDetached("not-a-key", "ittcsecscan-release", msg, sig) },
		"empty signature": func() error { return verifyDetached(pubLine(pub), "ittcsecscan-release", msg, nil) },
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: expected a fail-closed error, got nil (a bad signature must never verify)", name)
		}
	}
}

// The shipped built-in pack trust verifies (today: trusted-by-embedding, no pack key yet).
func TestVerifyBuiltinTrustPasses(t *testing.T) {
	var b strings.Builder
	if err := verifyBuiltinTrust(&b); err != nil {
		t.Fatalf("built-in pack trust must verify: %v", err)
	}
	if !strings.Contains(b.String(), "built-in packs:") {
		t.Errorf("unexpected output: %q", b.String())
	}
}
