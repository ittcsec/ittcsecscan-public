//go:build !unix && !windows

package store

import (
	"errors"
	"io/fs"
)

var errUnsupportedPlatform = errors.New("store: tenant file checks are not implemented on this platform")

func linkCount(string, fs.FileInfo) (uint64, error) { return 0, errUnsupportedPlatform }

func makePrivateDir(string) error { return errUnsupportedPlatform }
