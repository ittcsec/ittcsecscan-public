package sshsig

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

// testNamespace matches the namespace the ssh-keygen fixture in testdata was signed
// with, so the interop proof exercises the real tool's output.
const testNamespace = "ittcsecscan-pack"

// TestVerifyRealSSHKeygenSignature is the interop proof: the verifier accepts a
// signature produced by the real ssh-keygen, so the in-process implementation matches
// the tool that signs offline. The fixture was produced by ssh-keygen, not synthesized.
func TestVerifyRealSSHKeygenSignature(t *testing.T) {
	msg := readFixture(t, "message.txt")
	sig := readFixture(t, "message.txt.sig")
	pub := trustedFromFixture(t)

	got, err := Verify([]ed25519.PublicKey{pub}, testNamespace, msg, sig)
	if err != nil {
		t.Fatalf("real ssh-keygen signature did not verify: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("verified key does not match the trusted key")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	msg := readFixture(t, "message.txt")
	sig := readFixture(t, "message.txt.sig")
	pub := trustedFromFixture(t)

	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0x01
	if _, err := Verify([]ed25519.PublicKey{pub}, testNamespace, tampered, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered message: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	msg := readFixture(t, "message.txt")
	sig := readFixture(t, "message.txt.sig")
	pub := trustedFromFixture(t)

	blob, err := dearmor(sig)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0x01 // flip a byte of the ed25519 signature
	if _, err := Verify([]ed25519.PublicKey{pub}, testNamespace, msg, armor(blob)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered signature: err = %v, want ErrBadSignature", err)
	}
}

// TestVerifyRejectsWrongNamespace proves a signature in a different namespace (for
// example a release signature) does not validate under another namespace.
func TestVerifyRejectsWrongNamespace(t *testing.T) {
	priv, pub := genKey(t)
	msg := []byte("manifest")
	sig := mustSign(t, priv, "ittcsecscan-release", "sha512", msg)
	if _, err := Verify([]ed25519.PublicKey{pub}, testNamespace, msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong namespace: err = %v, want ErrBadSignature", err)
	}
}

// TestVerifyRejectsUntrustedKey proves a valid signature by a key that is not in the
// trust root is refused.
func TestVerifyRejectsUntrustedKey(t *testing.T) {
	signer, _ := genKey(t)
	_, trusted := genKey(t)
	msg := []byte("manifest")
	sig := mustSign(t, signer, testNamespace, "sha512", msg)
	if _, err := Verify([]ed25519.PublicKey{trusted}, testNamespace, msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("untrusted key: err = %v, want ErrBadSignature", err)
	}
}

// TestSignVerifyRoundTrip proves sign then verify for both sha512 and sha256, so the
// signed-data construction matches on the accept path too.
func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub := genKey(t)
	for _, alg := range []string{"sha512", "sha256"} {
		msg := []byte("secure updater " + alg)
		sig := mustSign(t, priv, testNamespace, alg, msg)
		if _, err := Verify([]ed25519.PublicKey{pub}, testNamespace, msg, sig); err != nil {
			t.Errorf("%s: round-trip signature did not verify: %v", alg, err)
		}
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	line := string(readFixture(t, "signer.pub"))
	got, err := ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(trustedFromFixture(t)) {
		t.Error("ParseAuthorizedKey returned a different key than the fixture")
	}
	if _, err := ParseAuthorizedKey("ssh-rsa AAAA..."); err == nil {
		t.Error("ParseAuthorizedKey accepted a non-ed25519 key")
	}
}

// --- helpers ---

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec // G304: fixed test fixture path, not untrusted input
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func trustedFromFixture(t *testing.T) ed25519.PublicKey {
	t.Helper()
	k, err := ParseAuthorizedKey(string(readFixture(t, "signer.pub")))
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}
	return k
}

func genKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, namespace, hashAlg string, message []byte) []byte {
	t.Helper()
	sig, err := Sign(priv, namespace, hashAlg, message)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
