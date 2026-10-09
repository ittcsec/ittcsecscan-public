package store

import "errors"

// Errors returned by the store. Callers test them with errors.Is.
var (
	// ErrInvalidTenantID reports a tenant ID that is not in canonical form.
	ErrInvalidTenantID = errors.New("store: invalid tenant ID")
	// ErrNotFound reports that no tenant with the requested ID exists.
	ErrNotFound = errors.New("store: tenant not found")
	// ErrUnsafePath reports a tenant path that is a link, junction, reparse
	// point, special file, or multiply linked file, or that resolves outside
	// the tenants root.
	ErrUnsafePath = errors.New("store: unsafe tenant path")
	// ErrExposed reports tenant files, or a folder above them, that other
	// accounts can read, change, or replace.
	ErrExposed = errors.New("store: tenant files are accessible to other accounts")
	// ErrForeignFile reports a database that is not this tenant's: a missing or
	// mismatched identity row, or a schema with triggers or views.
	ErrForeignFile = errors.New("store: database file does not belong to this tenant")
	// ErrKeyMismatch reports tenant keys that do not unwrap under the key
	// derived for the tenant, or a sealed value that fails authentication.
	ErrKeyMismatch = errors.New("store: keys or sealed data do not authenticate")
	// ErrUnsupportedSchema reports a tenant file this binary may not use: a
	// newer binary made a breaking change to it, so its min_reader_version is
	// above this binary's schema version (ADR-0011 §2). Nothing is written.
	ErrUnsupportedSchema = errors.New("store: unsupported tenant schema version")
	// ErrSchemaTampered reports a migration history that does not match the
	// migrations this binary ships: an edited checksum, an unknown or missing
	// migration, or versions that disagree with the history (ADR-0011 §2).
	ErrSchemaTampered = errors.New("store: tenant migration history does not match this binary")
	// ErrMigrationFailed reports a schema migration that did not complete. The
	// file is restored from the backup taken before it (ADR-0011 §2).
	ErrMigrationFailed = errors.New("store: schema migration failed")
	// ErrHardening reports a connection whose safety settings could not be
	// applied or verified.
	ErrHardening = errors.New("store: connection hardening failed")
	// ErrInUse reports an operation that needs a tenant nobody holds, or a
	// tenant that another process is migrating or restoring.
	ErrInUse = errors.New("store: tenant is in use")
	// ErrPoolExhausted reports that Acquire gave up waiting because every open
	// tenant stayed held. It never waits forever (Options.AcquireWait).
	ErrPoolExhausted = errors.New("store: no tenant slot became free")
	// ErrClosed reports use of a closed store or a released tenant handle.
	ErrClosed = errors.New("store: closed")
)
