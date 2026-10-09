//go:build windows

package fsperm

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func inspect(path string) (Report, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return Report{}, fmt.Errorf("reading the security descriptor of %s: %w", path, err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return Report{}, fmt.Errorf("identifying the current user: %w", err)
	}
	return evaluateSDDL(path, sd.String(), user.User.Sid.String(), windowsResolver)
}

// windowsResolver resolves machine- and domain-relative SDDL aliases (for
// example "LA", which Windows emits for the built-in Administrator account)
// through ConvertStringSidToSid, so they compare correctly with the current
// user's SID.
func windowsResolver(trustee string) string {
	if s := staticResolver(trustee); s != trustee {
		return s
	}
	if len(trustee) == 2 {
		if sid, err := windows.StringToSid(trustee); err == nil {
			return sid.String()
		}
	}
	return trustee
}
