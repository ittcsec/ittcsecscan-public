package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/report"
	"github.com/ittcsec/ittcsecscan/internal/sshsig"
)

// writeTrustBundle builds a report, writes report.json, signs it in the trust-report
// namespace with a fresh key, and writes the signature and the signer public key. It
// returns the three paths.
func writeTrustBundle(t *testing.T) (reportPath, sigPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	r := report.Build(report.Input{Tenant: "acme", ToolVersion: "0.1.0"})
	js, err := report.SignableBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig, err := sshsig.Sign(priv, report.TrustNamespace, "sha512", js)
	if err != nil {
		t.Fatal(err)
	}
	reportPath = filepath.Join(dir, "report.json")
	sigPath = filepath.Join(dir, "report.json.sig")
	pubPath = filepath.Join(dir, "signer.pub")
	for p, b := range map[string][]byte{reportPath: js, sigPath: sig, pubPath: []byte(pubLine(pub))} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return reportPath, sigPath, pubPath
}

// TestTrustCommandVerifies proves the trust command verifies a correctly signed report.
func TestTrustCommandVerifies(t *testing.T) {
	env := hermetic(t, nil)
	reportPath, sigPath, pubPath := writeTrustBundle(t)
	r := invoke(t, env, "trust", "--report", reportPath, "--sig", sigPath, "--signer", pubPath)
	if r.code != exitcode.OK {
		t.Fatalf("verify exit=%v err=%q", r.code, r.err)
	}
	if !strings.Contains(r.out, "VERIFIED") || !strings.Contains(r.out, "acme") {
		t.Errorf("verify output = %q", r.out)
	}
}

// TestTrustCommandFailsOnTamper proves a tampered report is rejected by the command (a
// non-OK exit), never reported verified.
func TestTrustCommandFailsOnTamper(t *testing.T) {
	env := hermetic(t, nil)
	reportPath, sigPath, pubPath := writeTrustBundle(t)
	b, err := os.ReadFile(reportPath) //nolint:gosec // G304: test file it just wrote
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), "acme", "evil", 1)
	if err := os.WriteFile(reportPath, []byte(tampered), 0o600); err != nil { //nolint:gosec // G703: test rewrites a temp file it created
		t.Fatal(err)
	}
	r := invoke(t, env, "trust", "--report", reportPath, "--sig", sigPath, "--signer", pubPath)
	if r.code == exitcode.OK {
		t.Fatalf("CRITICAL: tampered report verified: out=%q", r.out)
	}
}

// TestTrustCommandAttest proves attest mode checks self-consistency and prints how to sign
// and verify, without signing.
func TestTrustCommandAttest(t *testing.T) {
	env := hermetic(t, nil)
	reportPath, _, _ := writeTrustBundle(t)
	r := invoke(t, env, "trust", "--report", reportPath, "--attest")
	if r.code != exitcode.OK {
		t.Fatalf("attest exit=%v err=%q", r.code, r.err)
	}
	for _, want := range []string{"ssh-keygen -Y sign", report.TrustNamespace, "acme"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("attest output missing %q: %q", want, r.out)
		}
	}
}
