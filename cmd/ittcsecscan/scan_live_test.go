//go:build live

// This end-to-end test authenticates to a real cloud provider and reads from it.
// It is excluded from normal builds and CI by the "live" build tag and is run
// deliberately by the operator, against a test tenant with read-only
// credentials, with:
//
//	go test -tags live ./cmd/ittcsecscan/ -run TestScanLive
//
// It creates its own master key in a temporary directory; it never touches the
// operator's real data directory or key.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// TestScanLive runs a real scan through --create against whatever credentials
// the environment provides, and asserts the vertical works end to end: the
// command authenticates, collects, and stores a sealed scan. A completely
// covered scan exits OK; a scan with coverage gaps (for example limited IAM
// permissions) exits scan-incomplete. Both prove the pipeline; only a hard
// failure or a total auth failure is a problem.
func TestScanLive(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyFile := filepath.Join(root, "master.key")

	const pass = "live-test-passphrase-1234"
	if err := store.InitMasterKey(keyFile, 1, []byte(pass)); err != nil {
		t.Fatalf("init master key: %v", err)
	}
	read := func(string) ([]byte, error) { return []byte(pass), nil }

	r := invokeSecrets(hermetic(t, nil), read,
		"scan", "--create", "--data-dir", dataDir, "--master-key-file", keyFile, "--json")

	switch r.code {
	case exitcode.OK, exitcode.ScanIncomplete:
		// Both are healthy outcomes of a real scan; the difference is only how
		// much of the graph the credentials could read.
		t.Logf("scan exited %s\n%s", r.code, r.out)
	case exitcode.AuthFailed:
		t.Skipf("no usable cloud credentials in this environment: %s", r.err)
	default:
		t.Fatalf("scan failed: code=%s stderr=%q", r.code, r.err)
	}

	// A tenant was created and a scan stored under it.
	tenantsRoot := filepath.Join(dataDir, "tenants")
	entries, err := readDirNames(tenantsRoot)
	if err != nil {
		t.Fatalf("reading tenants root: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("tenants created = %d, want 1", len(entries))
	}
}

func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Readdirnames(-1)
}
