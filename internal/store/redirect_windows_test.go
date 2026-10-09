//go:build windows

package store

import (
	"encoding/binary"
	"io/fs"
	"os"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// Property 3 on Windows: junctions, which any user can create without a
// privilege, and access lists that let other accounts in are refused.

func TestJunctionedTenantDirectoryIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a, b := createTenant(t, s), createTenant(t, s)
	dirA := tenantDir(t, s, a)
	if err := os.Rename(dirA, dirA+"-moved"); err != nil {
		t.Fatal(err)
	}
	createJunction(t, dirA, tenantDir(t, s, b))
	requireRefused(t, s, a, ErrUnsafePath)
	acquire(t, s, b)
}

func TestJunctionedTenantsRootIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	a := createTenant(t, s)
	root := s.layout.tenantsRoot
	if err := os.Rename(root, root+"-moved"); err != nil {
		t.Fatal(err)
	}
	createJunction(t, root, root+"-moved")
	requireRefused(t, s, a, ErrUnsafePath)
}

func TestExposedTenantFilesAreRefusedWindows(t *testing.T) {
	me := testUserSID(t)
	for _, tc := range []struct {
		name string
		path func(s *Store, dir string) string
		dacl string
	}{
		{"database readable by Everyone", func(_ *Store, dir string) string { return dbPath(dir) },
			"D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)"},
		{"tenant directory modifiable by Authenticated Users", func(_ *Store, dir string) string { return dir },
			"D:P(A;OICI;FA;;;" + me + ")(A;OICI;0x1301bf;;;AU)"},
		// SDDL on files and folders: DT is FILE_DELETE_CHILD, DC is FILE_ADD_FILE.
		{"tenants root lets Authenticated Users delete entries", func(s *Store, _ string) string { return s.layout.tenantsRoot },
			"D:P(A;OICI;FA;;;" + me + ")(A;;DT;;;AU)"},
		{"tenants root lets Authenticated Users add entries", func(s *Store, _ string) string { return s.layout.tenantsRoot },
			"D:P(A;OICI;FA;;;" + me + ")(A;;DC;;;AU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			a := createTenant(t, s)
			setTestDACL(t, tc.path(s, tenantDir(t, s, a)), tc.dacl)
			requireRefused(t, s, a, ErrExposed)
		})
	}
}

func testUserSID(t *testing.T) string {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// setTestDACL replaces path's DACL with a protected one.
func setTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// createJunction makes link a directory junction (mount point) to target,
// the way `mklink /J` does, but without running a program.
func createJunction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	subst := utf16.Encode([]rune(`\??\` + target))
	display := utf16.Encode([]rune(target))
	var names []byte
	for _, u := range subst {
		names = binary.LittleEndian.AppendUint16(names, u)
	}
	names = append(names, 0, 0)
	for _, u := range display {
		names = binary.LittleEndian.AppendUint16(names, u)
	}
	names = append(names, 0, 0)
	if 8+len(names) > 0xffff {
		t.Fatal("junction target path too long")
	}
	buf := binary.LittleEndian.AppendUint32(nil, windows.IO_REPARSE_TAG_MOUNT_POINT)
	for _, v := range []int{8 + len(names), 0, 0, 2 * len(subst), 2*len(subst) + 2, 2 * len(display)} {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(v)) //nolint:gosec // G115: bounded by the 0xffff check above
	}
	buf = append(buf, names...)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil { //nolint:gosec // G115: len(buf) is below 64 KiB
		t.Fatalf("creating junction %s: %v", link, err)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode().Type()&fs.ModeIrregular == 0 {
		t.Fatalf("junction helper did not produce a reparse point: %v, %v", fi.Mode(), err)
	}
}
