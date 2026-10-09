//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

func setProtectedDACL(t *testing.T, path, dacl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(dacl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// Authenticated Users may delete entries in the parent folder, so the private
// data directory and configuration file inside it can be swapped out.
func TestDoctorFailsWhenAParentFolderAllowsDeletingEntries(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	setProtectedDACL(t, open, "D:P(A;OICI;FA;;;"+u.User.Sid.String()+")(A;;DT;;;AU)")
	data := filepath.Join(open, "data")
	cfgDir := filepath.Join(open, "cfg")
	for _, d := range []string{data, cfgDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"schema_version":1}`), 0o600); err != nil {
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
