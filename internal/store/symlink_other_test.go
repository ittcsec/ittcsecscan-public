//go:build !windows

package store

// symlinkNeedsPrivilege is never true outside Windows: creating a symlink
// needs no privilege, so a failure there must fail the test.
func symlinkNeedsPrivilege(error) bool { return false }
