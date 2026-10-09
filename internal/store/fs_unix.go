//go:build unix

package store

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// linkCount returns the number of hard links to the file described by fi.
func linkCount(_ string, fi fs.FileInfo) (uint64, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no stat information")
	}
	return widen(st.Nlink), nil
}

// widen converts Stat_t.Nlink, whose type differs by platform (uint16 on
// darwin, uint64 on linux), to uint64.
func widen[T ~uint16 | ~uint32 | ~uint64](n T) uint64 { return uint64(n) }

// makePrivateDir creates path with mode 0700; the umask can only remove bits.
// It fails if path exists. Default POSIX ACLs inherited from the parent are
// caught by private().
func makePrivateDir(path string) error {
	return os.Mkdir(path, 0o700)
}
