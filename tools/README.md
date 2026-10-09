# Development tools

Every tool used by CI and local checks is pinned here, one Go module per tool:

| Directory | Tool | Purpose |
|---|---|---|
| `golangci-lint/` | golangci-lint v2 | Lint, including gosec, depguard safety bans, bidichk |
| `govulncheck/` | golang.org/x/vuln | Reachability-aware vulnerability scanning |
| `gitleaks/` | gitleaks v8 | Secret scanning of the working tree and git history |
| `go-licenses/` | go-licenses v2 | Dependency license allow-list check |
| `cyclonedx-gomod/` | cyclonedx-gomod | CycloneDX SBOM for the CLI binary |

Build them all into `./bin` (git-ignored):

```sh
./tools/install.sh          # Linux, macOS, Git Bash
```

```powershell
.\tools\install.ps1          # Windows PowerShell
```

## Why one module per tool

A single shared `tools/go.mod` makes Go's minimal version selection pick one
version of every transitive dependency for *all* tools. In practice that
breaks tools: gitleaks failed to compile because golangci-lint required a newer
`charmbracelet/x/ansi`. Separate modules keep each tool on the dependency set
its maintainers tested. The tool modules are also isolated from the product
module, so none of their dependencies appear in the product's `go.sum` or SBOM.

## Updating a tool

```sh
go -C tools/<name> get -tool <module>@<version>
go -C tools/<name> mod tidy
```

Dependabot proposes updates for each directory (`.github/dependabot.yml`).
Review the release notes before merging: these tools gate every change.

## Vulnerable tool dependencies

CI scans every built tool with `govulncheck -mode=binary`, and a reachable
vulnerability fails the build. If the tool's latest release still carries the
vulnerable dependency, raise that dependency in the tool's module only:

```sh
go -C tools/<name> get <module>@<fixed version>
go -C tools/<name> mod tidy
./tools/install.sh
for b in bin/*; do ./bin/govulncheck -mode=binary "$b"; done
```

Such raises go beyond what the tool's maintainers tested, so CI's functional
checks (lint, gitleaks on the full history, the license check, SBOM
generation) must still pass. When upstream releases a fix, move back to its
own dependency set.
