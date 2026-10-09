# Schemas

Versioned JSON Schemas (draft 2020-12) for every external contract. The files
here are the source of truth. They are embedded into the binary
(`schemas/embed.go`) and Go types are tested against them.

| Path | Contract |
|---|---|
| `config/v1/config.schema.json` | Configuration file (ADR-0006) |
| `cli/v1/version.schema.json` | `ittcsecscan version --json` |
| `cli/v1/doctor.schema.json` | `ittcsecscan doctor --json` |
| `model/v1/common.schema.json` | Shared `$defs` for the canonical model (never validated against directly) |
| `model/v1/*.schema.json` | Canonical model documents (ADR-0014): entity, edge, permission, exposure, classification, evidence, scan_manifest, finding, attack_path, cut_set, remediation_plan. The Go types in `internal/model` are tested against these. |
| `permissions/v1/template.schema.json` | Least-privilege permission template (ADR-0016 §3). The data files live in `/permissions`; the `permissions` package loads and validates them. |
| `collect/v1/envelope.schema.json` | Collection evidence envelope (ADR-0018 §2). The `internal/collect` types are tested against it. |

Planned: rule and pack manifest; report model and receipts; update metadata and receipts.

## Identity

Every schema has a `$id` of the form `urn:ittcsecscan:schema:<area>:<name>:v<N>`.
URNs are deliberate: they cannot be dereferenced, and the validator refuses
every reference that is not embedded.

## Versioning and compatibility policy

1. **Major version per directory.** A schema's major version is part of its
   path (`v1/`) and `$id`. Documents carry `schema_version`.
2. **Frozen after release.** Once a release ships with a schema version, that
   file never changes in a way that rejects a previously valid document or
   accepts a document that old consumers would misread. Before the first
   release, v1 schemas may still change.
3. **Output schemas are closed** (`additionalProperties: false`), so adding an
   output field is a new major version. Producers may emit the old version on
   request during a deprecation window of at least one minor release.
4. **Input schemas** (configuration) are closed so that typos fail. The loader
   accepts every supported `schema_version` and migrates older documents
   forward in memory, never rewriting the operator's file silently.
5. **Deprecation** is announced in release notes one minor release before
   removal. Removing support for an input version is a breaking change.
6. **Tests:** each schema has a test proving the Go encoder's output validates,
   and at least one invalid fixture proving the constraint that matters most.
7. **No remote references.** Schemas may reference each other only by embedded
   `$id`.
