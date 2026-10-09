package report

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// signedTrustReport builds a report, serializes it, and signs those exact bytes with priv in
// the trust-report namespace, returning the JSON and the signature.
func signedTrustReport(t *testing.T, priv ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	r := Build(Input{Tenant: "acme", ToolVersion: "0.1.0", Started: "2026-01-01T00:00:00Z", Completed: "2026-01-01T00:05:00Z"})
	js, err := SignableBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(priv, TrustNamespace, "sha512", js)
	if err != nil {
		t.Fatal(err)
	}
	return js, sig
}

// TestVerifyTrustReportValid proves a correctly signed, unaltered report verifies and
// returns the report identity.
func TestVerifyTrustReportValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	js, sig := signedTrustReport(t, priv)
	r, err := VerifyTrustReport(js, sig, pub)
	if err != nil {
		t.Fatalf("valid trust report did not verify: %v", err)
	}
	if r.Tenant != "acme" || r.Hash == "" {
		t.Errorf("verified report identity wrong: %+v", r.Tenant)
	}
}

// TestVerifyTrustReportFailsClosed proves every tampering is rejected, never a pass: an
// altered body, a wrong key, a wrong namespace, and a truncated signature all error.
func TestVerifyTrustReportFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	js, sig := signedTrustReport(t, priv)

	t.Run("altered body", func(t *testing.T) {
		tampered := bytes.Replace(js, []byte("acme"), []byte("evil"), 1)
		if _, err := VerifyTrustReport(tampered, sig, pub); err == nil {
			t.Fatal("CRITICAL: an altered report verified")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		otherPub, _, _ := ed25519.GenerateKey(nil)
		if _, err := VerifyTrustReport(js, sig, otherPub); err == nil {
			t.Fatal("CRITICAL: a report verified against the wrong key")
		}
	})
	t.Run("wrong namespace", func(t *testing.T) {
		wrongNS, err := sshsig.Sign(priv, "ittcsecscan-pack", "sha512", js)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyTrustReport(js, wrongNS, pub); err == nil {
			t.Fatal("CRITICAL: a signature from another namespace verified as a trust report")
		}
	})
	t.Run("truncated signature", func(t *testing.T) {
		if _, err := VerifyTrustReport(js, sig[:len(sig)/2], pub); err == nil {
			t.Fatal("CRITICAL: a truncated signature verified")
		}
	})
	t.Run("empty signature", func(t *testing.T) {
		if _, err := VerifyTrustReport(js, nil, pub); err == nil {
			t.Fatal("CRITICAL: an empty signature verified")
		}
	})
}

// TestCheckSelfConsistentCatchesHashMismatch proves a report whose embedded hash no longer
// matches its body is rejected before any signature is considered.
func TestCheckSelfConsistentCatchesHashMismatch(t *testing.T) {
	r := Build(Input{Tenant: "acme", ToolVersion: "0.1.0"})
	js, err := SignableBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	// Alter a value without recomputing the hash: the body no longer matches r.Hash.
	tampered := bytes.Replace(js, []byte("acme"), []byte("acyz"), 1)
	if _, err := CheckSelfConsistent(tampered); !errors.Is(err, ErrReportHashMismatch) {
		t.Fatalf("hash mismatch not caught: %v", err)
	}
	// The untampered report is self-consistent.
	if _, err := CheckSelfConsistent(js); err != nil {
		t.Fatalf("valid report reported inconsistent: %v", err)
	}
}

// TestSignableBytesIsReportJSON proves the signed bytes are exactly the authoritative
// report.json, so what an operator signs is what a recipient reads.
func TestSignableBytesIsReportJSON(t *testing.T) {
	r := Build(Input{Tenant: "acme", ToolVersion: "0.1.0"})
	a, err := SignableBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("SignableBytes differs from the report.json bytes")
	}
}
