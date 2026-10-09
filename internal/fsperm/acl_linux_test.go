//go:build linux

package fsperm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func setACL(t *testing.T, path, name string, entries ...aclEntry) {
	t.Helper()
	err := unix.Setxattr(path, name, acl(entries...), 0)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skipf("filesystem at %s does not support POSIX ACLs", path)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestInspectLinuxACLs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Mode bits stay owner-only (group bits show the mask), but a named user
	// is granted read and write through the ACL.
	setACL(t, dir, "system.posix_acl_access",
		aclEntry{aclUserObj, 7, 0}, aclEntry{aclUser, 6, 65534}, aclEntry{aclGroupObj, 0, 0},
		aclEntry{aclMask, 6, 0}, aclEntry{aclOther, 0, 0})
	setACL(t, dir, "system.posix_acl_default",
		aclEntry{aclUserObj, 7, 0}, aclEntry{aclGroupObj, 0, 0}, aclEntry{aclGroup, 4, 65534},
		aclEntry{aclMask, 4, 0}, aclEntry{aclOther, 0, 0})

	rep, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Describe(); got != "user uid 65534 (read, write)" {
		t.Errorf("Describe() = %q", got)
	}
	if got := rep.DescribeInherited(); got != "group gid 65534 (read)" {
		t.Errorf("DescribeInherited() = %q", got)
	}
}
