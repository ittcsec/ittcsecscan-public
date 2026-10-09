//go:build windows

package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

// symlinkNeedsPrivilege reports the one accepted reason to skip a symlink
// test: the account lacks SeCreateSymbolicLinkPrivilege (and Developer Mode
// is off).
func symlinkNeedsPrivilege(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}
