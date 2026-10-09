package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/ittcsec/ittcsecscan/internal/fsperm"
)

// plainDir returns path's FileInfo, refusing anything but an ordinary
// directory. Go reports symlinks as ModeSymlink and junctions and other
// reparse points as ModeIrregular, so both are refused here.
func plainDir(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Type() != fs.ModeDir {
		return nil, fmt.Errorf("%w: %s is not a plain directory (%v)", ErrUnsafePath, path, fi.Mode().Type())
	}
	return fi, nil
}

// plainFile refuses anything but an ordinary file with exactly one hard link.
// A second link would let another path, possibly another tenant's, reach the
// same data.
func plainFile(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a plain file (%v)", ErrUnsafePath, path, fi.Mode().Type())
	}
	n, err := linkCount(path, fi)
	if err != nil {
		return nil, fmt.Errorf("%w: counting hard links of %s: %w", ErrUnsafePath, path, err)
	}
	if n != 1 {
		return nil, fmt.Errorf("%w: %s has %d hard links", ErrUnsafePath, path, n)
	}
	return fi, nil
}

// checkSidecarsPlain applies plainFile to each SQLite sidecar that exists.
func checkSidecarsPlain(db string) error {
	for _, p := range sidecars(db) {
		if _, err := plainFile(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// private refuses path when another account can read, change, or replace it,
// or would inherit access to entries created in it. A check that cannot see
// every mechanism (macOS ACLs, unreadable without cgo) is accepted, and the
// owner-only mode bits are then the evidence (threat model residual item 3).
func private(path string) error {
	rep, err := fsperm.Inspect(path)
	if err != nil {
		return fmt.Errorf("%w: inspecting %s: %w", ErrExposed, path, err)
	}
	if rep.OthersCanRead() || rep.OthersCanWrite() {
		return fmt.Errorf("%w: %s: %s", ErrExposed, path, rep.Describe())
	}
	if len(rep.Inherited) > 0 {
		return fmt.Errorf("%w: entries created in %s would inherit access: %s", ErrExposed, path, rep.DescribeInherited())
	}
	return nil
}

// privateAncestors refuses path when another account can replace any folder
// above it, as written or symlink-resolved.
func privateAncestors(path string) error {
	reps, err := fsperm.InspectAncestors(path)
	if err != nil {
		return fmt.Errorf("%w: inspecting folders above %s: %w", ErrExposed, path, err)
	}
	if len(reps) > 0 {
		return fmt.Errorf("%w: another account can replace %s, above %s", ErrExposed, reps[0].Path, path)
	}
	return nil
}

// ensurePrivateDir creates path owner-only when it is missing, then requires
// it to be a plain, owner-only directory.
func ensurePrivateDir(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := makePrivateDir(path); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("store: creating %s: %w", path, err)
		}
	}
	if _, err := plainDir(path); err != nil {
		return err
	}
	return private(path)
}

// createPrivateFile creates path exclusively with owner-only permissions. It
// fails if anything already exists at path.
func createPrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path comes only from layout.dir, a validated tenant ID under the data directory
	if err != nil {
		return err
	}
	return f.Close()
}
