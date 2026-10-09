package fsperm

import "strings"

// sidTrustedInstaller is NT SERVICE\TrustedInstaller. It owns and services
// Windows system folders (the drive root included) with SYSTEM-level
// authority; only SYSTEM can act as it.
const sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// systemPrincipal reports Windows principals that can already read and change
// every file on the machine, so their access is not an exposure.
func systemPrincipal(sid string) bool {
	return sid == sidSystem || sid == sidAdministrators || sid == sidTrustedInstaller
}

// appContainerSID reports AppContainer package (S-1-15-2-*) and capability
// (S-1-15-3-*) SIDs. They are not accounts. Windows grants a sandboxed process
// access only if both its account and its package or capability pass the
// access check, so these entries never give another account access. Windows
// places them on the user's own profile folders (for example
// %LOCALAPPDATA%).
func appContainerSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-15-2-") || strings.HasPrefix(sid, "S-1-15-3-")
}
