//go:build windows

package store

import (
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// linkCount returns the number of hard links to path, read from the file
// itself without following a reparse point.
func linkCount(path string, _ fs.FileInfo) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}

// makePrivateDir creates path and replaces its DACL with a protected one that
// grants full control only to the current user, SYSTEM, and Administrators,
// inherited by everything created inside. It fails if path exists.
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	me, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return fmt.Errorf("building owner-only DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("reading owner-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("applying owner-only DACL to %s: %w", path, err)
	}
	return nil
}

func currentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("reading the current user: %w", err)
	}
	return u.User.Sid.String(), nil
}
