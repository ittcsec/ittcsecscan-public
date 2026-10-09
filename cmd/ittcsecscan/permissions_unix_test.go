//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

func TestDoctorFailsOnWorldWritableConfig(t *testing.T) {
	cfg := writeConfig(t, `{"schema_version":1}`)
	if err := os.Chmod(cfg, 0o666); err != nil { //nolint:gosec // G302: the test deliberately makes the config world-writable
		t.Fatal(err)
	}
	r := invoke(t, hermetic(t, nil), "doctor", "--json", "--config", cfg)
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v, want doctor-failed", r.code)
	}
	rep := decodeDoctor(t, r)
	if got := checkStatus(rep, "config.load"); got != "pass" {
		t.Errorf("config.load = %s; the file itself is valid", got)
	}
	if got := checkStatus(rep, "config.permissions"); got != "fail" {
		t.Errorf("config.permissions = %s, want fail", got)
	}
}

func TestDoctorFailsOnWorldWritableDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: the test deliberately makes the data directory world-writable
		t.Fatal(err)
	}
	r := invoke(t, hermetic(t, nil), "doctor", "--json", "--data-dir", dir)
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v, want doctor-failed", r.code)
	}
	if got := checkStatus(decodeDoctor(t, r), "filesystem.data_dir"); got != "fail" {
		t.Errorf("filesystem.data_dir = %s, want fail", got)
	}
}
