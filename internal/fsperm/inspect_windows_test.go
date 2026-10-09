//go:build windows

package fsperm

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// setDACL replaces path's DACL with a protected (non-inheriting) one.
func setDACL(t *testing.T, path, dacl string) {
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

func TestInspectWindowsACLs(t *testing.T) {
	me := currentUserSID(t)
	tests := []struct {
		name  string
		dacl  string
		read  bool
		write bool
	}{
		{"owner only", "D:P(A;OICI;FA;;;" + me + ")", false, false},
		{"owner, SYSTEM, Administrators", "D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false, false},
		{"Authenticated Users modify", "D:P(A;OICI;FA;;;" + me + ")(A;OICI;0x1301bf;;;AU)", true, true},
		{"Users read and execute", "D:P(A;OICI;FA;;;" + me + ")(A;OICI;0x1200a9;;;BU)", true, false},
		{"Everyone WRITE_DAC", "D:P(A;;FA;;;" + me + ")(A;;WD;;;WD)", false, true},
	}
	for _, tt := range tests {
		for _, dir := range []bool{true, false} {
			p := filepath.Join(t.TempDir(), "entry")
			if dir {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			setDACL(t, p, tt.dacl)
			rep, err := Inspect(p)
			if err != nil {
				t.Fatal(err)
			}
			if rep.OthersCanRead() != tt.read || rep.OthersCanWrite() != tt.write {
				t.Errorf("%s (dir=%v): read=%v write=%v, want read=%v write=%v (%s)",
					tt.name, dir, rep.OthersCanRead(), rep.OthersCanWrite(), tt.read, tt.write, rep.Describe())
			}
		}
	}
}

func TestInspectMissing(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}
