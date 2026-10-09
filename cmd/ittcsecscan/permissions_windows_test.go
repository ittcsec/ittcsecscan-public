//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

// grantAuthenticatedUsersModify replaces path's DACL with one that also lets
// every signed-in account modify it: what a folder created under a drive root
// typically inherits.
func grantAuthenticatedUsersModify(t *testing.T, path string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + u.User.Sid.String() + ")(A;OICI;0x1301bf;;;AU)")
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

func TestDoctorFailsOnSharedWritableConfig(t *testing.T) {
	cfg := writeConfig(t, `{"schema_version":1}`)
	grantAuthenticatedUsersModify(t, cfg)
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

func TestDoctorFailsOnSharedWritableDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	grantAuthenticatedUsersModify(t, dir)
	r := invoke(t, hermetic(t, nil), "doctor", "--json", "--data-dir", dir)
	if r.code != exitcode.DoctorFailed {
		t.Fatalf("exit = %v, want doctor-failed", r.code)
	}
	if got := checkStatus(decodeDoctor(t, r), "filesystem.data_dir"); got != "fail" {
		t.Errorf("filesystem.data_dir = %s, want fail", got)
	}
}
