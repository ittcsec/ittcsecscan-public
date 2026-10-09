# Permission templates

The least-privilege, read-only permissions ittcsecscan requires from each cloud
provider, one file per provider per profile (ADR-0016 §3).

```
permissions/<provider>/<profile>.json    aws|azure|gcp × discovery|deep-evidence|remediation
```

Each file is validated against `schemas/permissions/v1/template.schema.json` and
loaded by the `permissions` package.

## Deliberately empty (for now)

A least-privilege permission is justified by the collector or rule that needs
it, and those arrive with the collectors and the rule engine. Until then these templates are
**honestly empty**. Seeding them from a broad managed role (AWS `ReadOnlyAccess`,
Azure `Reader`, GCP `roles/viewer`) was rejected: that is not a least-privilege
template, and labelling it as one would imply a scope narrowing that has not
happened. The zero-permission identity probe (`auth plan`) already proves
authentication works; the templates stay empty until real requirements exist.

## How they stay honest

- **Two-directional reconciliation** (`TestTemplatesMatchDeclaredRequirements`):
  every permission a collector declares must appear in the matching template
  crediting that collector, and every permission a template grants must be
  required by a declared collector or rule. An invented or an orphaned
  permission is a build failure, not something a reviewer must catch.
- **Verification gate** (schema + `TestSchemaRejectsVerifiedWithoutEvidence`): a
  template or permission may claim `verified` only with a recorded date and
  method. It is verified by the maintainer-run live harness in `permissions/live`
  against a real, disposable test account, never in CI.
- **Overbroad detection** is report-only and inert until a template is
  populated: against an empty template every grant would look excess.

## OAuth scope vs granted permissions (GCP)

A permission template lists the provider permissions a credential must be
granted. On GCP there is a second, coarser gate: the OAuth scope the access
token carries. These are not the same thing, and for GCP the scope is
deliberately broader than the permissions.

The GCP scan requests the `https://www.googleapis.com/auth/cloud-platform`
OAuth scope for collection, because the first collected read
(`iam.serviceAccounts.list`) accepts no read-only-named scope: Google's IAM API
offers only `cloud-platform` (or the `iam` scope), never
`cloud-platform.read-only` (IAM API reference, verified 2026-09-18). The OAuth
scope is an upper bound on what a token could do. What actually keeps the
collection read-only is the **granted IAM permissions**: this discovery template
pins them to read-only operations only (for example `iam.serviceAccounts.list`).
Grant the credential a read-only role; the broad scope cannot widen what the
credential is permitted to do. The identity probe (`auth plan`) requests only the
narrow `userinfo.email` scope, so only a scan ever requests `cloud-platform`.
