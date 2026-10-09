//go:build darwin

package fsperm

// macOS ACLs can grant access that mode bits do not show, and reading them
// needs acl_get_file (cgo) or getattrlist with unsafe, both excluded by
// ADR-0001 and the lint rules. Results are therefore marked incomplete.
func extendedACLs(string, bool) (access, deflt []byte, incomplete string, err error) {
	return nil, nil, "macOS ACLs are not inspected, and they can grant access that file modes do not show", nil
}
