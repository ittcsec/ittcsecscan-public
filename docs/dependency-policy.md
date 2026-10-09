# Dependency policy

Every dependency runs inside a process that holds cloud credentials. This
policy applies to the product module (`go.mod` at the repository root), to the
pinned tool modules (`tools/*/go.mod`), and to CI actions.

## Adding a product dependency

Prefer the standard library. A new dependency needs, in the pull request:

1. **Necessity:** what it does that the standard library or existing
   dependencies cannot, and the size of the code it saves.
2. **License:** on the allow-list below (the CI license check enforces it).
3. **Maintenance:** recent releases, responsive maintainers, no open,
   unaddressed security reports.
4. **Security history:** past CVEs and how they were handled; `govulncheck`
   is clean.
5. **Footprint:** transitive dependencies it adds (`go mod graph`), no cgo, no
   network or filesystem side effects at import time, no `init` that alters
   global state.
6. **Security review approval** (CODEOWNERS covers `go.mod`/`go.sum`).

Architecture-level dependencies (SQLite driver, cloud SDKs, rule language,
PDF/DOCX renderers, TUF client) additionally need an ADR.

## Licenses

| Allowed | Case-by-case (ADR and legal review) | Prohibited |
|---|---|---|
| Apache-2.0, BSD-2-Clause, BSD-3-Clause, MIT, ISC | MPL-2.0 | GPL, LGPL, AGPL, SSPL, BUSL, Commons Clause, proprietary, unknown or missing |

The allow-list is enforced by `go-licenses check` in CI. Development tools are
not linked into the product, but their licenses must still permit use in CI.

## Integrity

- `go.sum` is committed. CI runs `go mod verify`.
- The public Go module proxy and checksum database stay enabled. `GONOSUMDB`,
  `GONOSUMCHECK`, `GOINSECURE`, and `GOFLAGS=-insecure` are prohibited in CI
  and release builds.
- `replace` directives pointing at forks or local paths need an ADR.
- **The product module is vendored** (ADR-0017): `vendor/` is committed, and
  builds, tests, and the release use `GOFLAGS=-mod=vendor`, so the code that
  runs with the operator's cloud credentials is in-tree, reviewable, and builds
  offline. CI regenerates `vendor/` and fails on any drift. Supply-chain
  analysis tools that read module metadata rather than compiled code run in
  module mode: `go-licenses` uses `GOFLAGS=-mod=mod`. The pinned tools under
  `tools/` are separate modules and are not vendored (they build with
  `-mod=readonly`).
- The Go toolchain is pinned in `go.mod` (`toolchain` directive) and CI uses
  `GOTOOLCHAIN=local`.
- The Go toolchain is pinned in `go.mod` (`toolchain` directive) and CI uses
  `GOTOOLCHAIN=local`.

## Tools

- Pinned in one module per tool under `tools/` (ADR-0007); built from source
  by `tools/install.sh`.
- Updated through Dependabot pull requests. Read the release notes: tools gate
  every change.
- **Tools are scanned too.** CI runs `govulncheck -mode=binary` on every built
  tool binary. A reachable vulnerability in a tool blocks merge exactly like
  one in the product.
- **Fixing a vulnerable tool dependency.** When upstream has not released a
  fix, raise the vulnerable indirect dependency inside that tool's own module:
  `go -C tools/<name> get <module>@<fixed version>`, then `go mod tidy`. This
  stays within the tool's module and never touches the product. The
  functional checks in CI (lint, secret scan, license check, SBOM) must still
  pass.

## CI actions

- Only actions owned by GitHub (`actions/*`) are used today. Adding a
  third-party action needs security review.
- Every action is pinned by **full commit SHA** with the version in a comment.
- Workflows use a read-only `GITHUB_TOKEN`, `persist-credentials: false`, and
  never `pull_request_target`.

## Updates and vulnerabilities

- Dependabot opens weekly update PRs for `/`, `/tools/*`, and GitHub Actions.
- `govulncheck` runs on every PR. A reachable vulnerability blocks merge unless
  a time-boxed exception with a mitigation is recorded in the PR.
- Remove dependencies that are no longer needed; `go mod tidy -diff` in CI
  catches drift.

## Current product dependencies

| Module | License | Why |
|---|---|---|
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | JSON Schema 2020-12 validation of configuration and CLI output (ADR-0006) |
| `golang.org/x/sys` | BSD-3-Clause | Windows token elevation check in `doctor`; Windows security descriptors in `fsperm`. The store uses it for owner-only DACLs and hard-link counts. |
| `golang.org/x/text` (indirect) | BSD-3-Clause | Required by jsonschema for localized messages |
| `modernc.org/sqlite` | BSD-3-Clause (SQLite itself is public domain) | Pure-Go SQLite driver, one database file per tenant. Confirmed in ADR-0003, which records its evaluation, and used as ADR-0010 requires. No cgo. |
| `modernc.org/libc`, `modernc.org/mathutil`, `modernc.org/memory` (indirect) | BSD-3-Clause | Runtime of the SQLite translation |
| `github.com/remyoudompheng/bigfft` (indirect) | BSD-3-Clause | Used by `modernc.org/mathutil` |
| `github.com/dustin/go-humanize`, `github.com/google/uuid`, `github.com/mattn/go-isatty`, `github.com/ncruces/go-strftime` (indirect) | MIT | Small helpers required by `modernc.org/sqlite` and `modernc.org/libc` |
