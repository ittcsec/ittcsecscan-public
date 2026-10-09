// Package store keeps each tenant's data in its own SQLite database file
// (ADR-0003, ADR-0010).
//
// Layout: <data_dir>/tenants/<tenant-id>/, one directory per tenant, holding
// store.db, blobs/, and, once a migration has run, backups/ (pre-migration
// backups) and migrate.lock. There is no shared database file. A tenant is
// opened only by its TenantID, through Store.Acquire; no API accepts a
// database path.
//
// What this package enforces today:
//   - Tenant IDs are 128 random bits in canonical base32, and a single
//     function turns a validated ID into a path.
//   - Tenant directories and files must be plain (no symlink, junction,
//     reparse point, or second hard link), owner-only, and beneath folders no
//     other account can replace.
//   - Every file identifies its own tenant, and its keys must unwrap under the
//     key derived from the operator's master key for that tenant.
//   - Each open tenant has exactly one connection, hardened before use:
//     ATTACH is impossible, trusted_schema is off, defensive mode is on.
//   - The version-1 canonical schema (migrations/0002, ADR-0011): every table
//     refuses rows of any other tenant through a per-file CHECK constraint,
//     no index contains tenant_id, and every foreign key is indexed.
//   - Values are sealed with AES-256-GCM, bound to the tenant, to a stable
//     logical field name, and to the row's key, so renaming a table or column
//     never breaks decryption (ADR-0013). Stable IDs and every hash of
//     customer content are per-tenant HMACs.
//   - Schema migrations are numbered, embedded, and checksummed. A file whose
//     history does not match this binary's migrations, or that a newer binary
//     changed incompatibly, is refused before anything is written. An older
//     file is backed up, migrated one transaction per migration under a
//     per-tenant lock, and restored from the backup if any step fails.
//     Contract migrations are gated until the shared open lock (ADR-0012).
//   - A bounded pool keeps at most MaxOpen tenants open.
//
// Not yet here: ingest of later scans (change detection and change records;
// today only a new tenant's first scan loads), the repository interfaces,
// retention deletion, migration steps written in Go, evidence blobs, tenant
// aliases, and the OS keystore or operator-supplied master-key sources.
package store
