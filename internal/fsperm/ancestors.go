package fsperm

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// InspectAncestors checks every directory above path, from its parent up to
// the filesystem root, and returns the reports of those in which an untrusted
// principal can delete or rename entries. Such a principal could move path, or
// a folder containing it, aside and put its own in place. This is the check
// OpenSSH applies to key and configuration paths.
//
// Both the path as written and its symlink-free form are walked. Directories
// that do not exist yet are skipped, so path itself may be missing (a data
// directory before first use).
func InspectAncestors(path string) ([]Report, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	w := ancestorWalk{seen: map[string]bool{}}
	if err := w.walk(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	real, err := resolveExisting(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", path, err)
	}
	if err := w.walk(real); err != nil {
		return nil, err
	}
	return w.found, nil
}

type ancestorWalk struct {
	seen  map[string]bool
	found []Report
}

func (w *ancestorWalk) walk(dir string) error {
	for {
		if !w.seen[dir] {
			w.seen[dir] = true
			rep, err := inspect(dir)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// Not created yet; the folders above decide who could create it.
			case err != nil:
				return fmt.Errorf("inspecting %s: %w", dir, err)
			case rep.OthersCanReplace():
				w.found = append(w.found, rep)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// resolveExisting returns the symlink-free form of the deepest existing
// directory at or above dir.
func resolveExisting(dir string) (string, error) {
	for {
		real, err := filepath.EvalSymlinks(dir)
		if err == nil {
			return real, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", err
		}
		dir = parent
	}
}
