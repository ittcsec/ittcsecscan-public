//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

// A private data directory and configuration file inside a folder that other
// accounts can write (without the sticky bit) can be swapped out, so doctor
// must fail both checks.
func TestDoctorFailsWhenAParentFolderIsWorldWritable(t *testing.T) {
	open := filepath.Join(t.TempDir(), "shared")
	data := filepath.Join(open, "data")
	cfgDir := filepath.Join(open, "cfg")
	for _, d := range []string{open, data, cfgDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: the test needs a folder others can write
		t.Fatal(err)
	}

	r := invoke(t, hermetic(t, nil), "doctor", "--json", "--config", cfg, "--data-dir", data)
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v, want doctor-failed", r.code)
	}
	rep := decodeDoctor(t, r)
	for _, id := range []string{"config.permissions", "filesystem.data_dir"} {
		if got := checkStatus(rep, id); got != "fail" {
			t.Errorf("%s = %s, want fail", id, got)
		}
	}
}
