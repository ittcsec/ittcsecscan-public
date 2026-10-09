//go:build linux

package fsperm

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// extendedACLs returns the raw POSIX access ACL and, for directories, the
// default ACL. Both are nil when the entry has none or the filesystem does not
// support them.
func extendedACLs(path string, isDir bool) (access, deflt []byte, incomplete string, err error) {
	if access, err = readXattr(path, "system.posix_acl_access"); err != nil {
		return nil, nil, "", err
	}
	if isDir {
		if deflt, err = readXattr(path, "system.posix_acl_default"); err != nil {
			return nil, nil, "", err
		}
	}
	return access, deflt, "", nil
}

func readXattr(path, name string) ([]byte, error) {
	for range 3 {
		size, err := unix.Getxattr(path, name, nil)
		if absent(err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s of %s: %w", name, path, err)
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		n, err := unix.Getxattr(path, name, buf)
		switch {
		case errors.Is(err, unix.ERANGE):
			continue // the attribute grew between the two calls
		case absent(err):
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("reading %s of %s: %w", name, path, err)
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("reading %s of %s: attribute size kept changing", name, path)
}

// absent reports errors meaning "no such ACL": the attribute is not set, or
// the filesystem does not support it.
func absent(err error) bool {
	return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP)
}
