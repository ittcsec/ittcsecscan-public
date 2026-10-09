package store

import (
	"errors"
	"fmt"
	"os"
)

// errLocked reports a file lock held by another process or handle.
var errLocked = errors.New("lock held")

// lockForMigration takes the tenant's migration lock without waiting
// (ADR-0012 §2). Only one process at a time may back up, migrate, or restore
// a tenant, so one process's restore can never undo another's migration. The
// lock file is kept; the OS releases the lock if the process dies. The lock
// does not stop a process that already has the tenant open, which is why
// contract migrations are gated (ADR-0012 §3, threat T-28).
func lockForMigration(dir string) (unlock func() error, err error) {
	p := lockPath(dir)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: p is inside a tenant directory named by a validated tenant ID
	if err != nil {
		return nil, fmt.Errorf("store: opening the migration lock: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	// Refuse a planted link, junction, or special file: the file on disk must
	// be the plain, owner-only file just opened.
	onDisk, err := plainFile(p)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(onDisk, opened) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrUnsafePath, p)
	}
	if err := private(p); err != nil {
		return nil, err
	}
	if err := tryLockFile(f); err != nil {
		if errors.Is(err, errLocked) {
			return nil, fmt.Errorf("%w: another process is migrating or restoring this tenant", ErrInUse)
		}
		return nil, fmt.Errorf("store: taking the migration lock: %w", err)
	}
	return func() error { return errors.Join(unlockFile(f), f.Close()) }, nil
}
