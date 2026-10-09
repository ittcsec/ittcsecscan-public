//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package store

import (
	"errors"
	"os"
)

// errNoFileLocking refuses migrations where no file lock is implemented,
// rather than migrating without one.
var errNoFileLocking = errors.New("store: file locking is not implemented on this platform")

func tryLockFile(*os.File) error { return errNoFileLocking }

func unlockFile(*os.File) error { return errNoFileLocking }
