# Contributing to ittcsecscan

ittcsecscan is security software that runs with access to customers' cloud
control planes. The rules below exist to keep it trustworthy; they are not
optional for any contributor, human or AI-assisted.

## Ground rules

1. **Never weaken a safety invariant** to make a test pass or a feature ship.
   Unknown, denied, timed-out, or missing data is never reported as a pass; it
   is modelled explicitly. Credentials are never stored, and secret values are
   never retrieved.
2. **Do not invent provider semantics.** Cite official AWS, Azure, or Google
   Cloud documentation, and back permissions with live access-denied tests
   against test tenants. Represent unsupported or incomplete behaviour
   explicitly.
3. **Test tenants only.** Never use production cloud accounts or real customer
   data in development, fixtures, issues, or pull requests.
4. **Read-only by default.** Collectors read; they never write. Remediation is
   plan-only and never executes a change without an approved plan.

## Every change

A change is done when it builds, passes every CI check, and (for the areas
below) has had security review. Write a clear description of what changed and
why.

### Areas that require human security review

Changes touching any of these need human security review:

- authentication and credential handling (`internal/auth`);
- updates and trust metadata (`internal/update`);
- pack loading and rule execution (`internal/rules`, `packs/`);
- multi-tenancy and storage (`internal/store`, `internal/model`);
- redaction and output safety (`internal/redact`, `internal/logging`,
  `internal/termsafe`, `internal/report`);
- remediation (`internal/remediate`);
- CI, release, tooling, and dependencies (`.github/`, `release/`, `tools/`,
  `go.mod`).

## Coding rules

These rules are enforced by `.golangci.yml` wherever a linter can enforce them:

- **No process execution.** `os/exec` is banned: provider changes use SDK
  calls, never composed shell commands.
- **No run-time code loading.** `plugin` is banned; packs are declarative.
- **Log only through `internal/logging`.** The standard `log` package is
  banned. Wrap in-memory secrets in `redact.Secret`.
- **No ambient process state outside `main.go`.** Read the environment through
  an injected `config.LookupEnv`; write output to injected `io.Writer`s.
- **Escape untrusted text for its sink.** Terminal output goes through
  `termsafe`; errors shown to users go through `redact.String`. Report
  renderers must escape for each output format.
- **Unknown is not pass.** Never map an error, denial, timeout, or missing
  data to a passing state. Model it explicitly.
- **Honour `context.Context`.** Every blocking or long-running operation takes
  a context and stops when it is cancelled.
- **Stable contracts.** Exit codes (`internal/exitcode`) may be added, never
  renumbered. Schemas follow `schemas/README.md`.

## Local checks

Install Go 1.27.1 (the version pinned by `go.mod`), then build the pinned
tools once:

```sh
./tools/install.sh        # or .\tools\install.ps1 on Windows
```

Run the same checks as CI:

```sh
gofmt -l .
go vet ./...
go mod tidy -diff
./bin/golangci-lint run ./...
go test -count=1 -shuffle=on ./...
go test -race -count=1 ./...          # needs cgo and a C compiler
go test -run='^$' -fuzz='^FuzzString$'   -fuzztime=30s ./internal/redact
go test -run='^$' -fuzz='^FuzzSanitize$' -fuzztime=30s ./internal/termsafe
go test -run='^$' -fuzz='^FuzzDecode$'   -fuzztime=30s ./internal/config
./bin/govulncheck ./...
./bin/gitleaks dir --no-banner --redact .
./bin/go-licenses check ./... --allowed_licenses=Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT,ISC --ignore github.com/ittcsec/ittcsecscan
```

On Windows, prefix the binaries with `.\bin\` and add `.exe`.

## Dependencies

Read [docs/dependency-policy.md](docs/dependency-policy.md) before adding one.
New product dependencies need a justification in the pull request and security
review.

## Commits and branches

- Changes arrive by pull request; nothing is pushed to `main` directly. Branch
  protection on `main` requires a pull request, every CI job passing, the
  branch up to date, conversations resolved, and no force pushes.
- One coherent change per pull request.
- Write commit messages that explain *why*.
- Commits reaching `main` must be signed; GitHub enforces this. Sign with an
  SSH key registered on GitHub as a *signing* key:
  `git config gpg.format ssh`,
  `git config user.signingkey <path to the .pub file>`,
  `git config commit.gpgsign true`.
  Merge commits created on GitHub are signed by GitHub.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
