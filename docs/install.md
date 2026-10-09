# Installing ittcsecscan

ittcsecscan ships as a single static binary per platform, with a signed checksum file so you
can verify what you downloaded before running it. It is local-first and read-only by default.

> No public release has shipped yet. Until 1.0.0, build from source on `main`. The download
> steps below describe the release format that the release workflow produces
> ([release/README.md](../release/README.md), [ADR-0009](adr/0009-release-signing-and-provenance.md)).

## Platforms

Reproducible static binaries are built for:

- **Linux**: amd64, arm64
- **macOS**: amd64 (Intel), arm64 (Apple silicon)
- **Windows**: amd64, arm64

Release builds are `CGO_ENABLED=0`, so there is no runtime dependency.

## Build from source

Requires Go 1.27.x. The module is vendored, so no network fetch is needed.

```sh
git clone https://github.com/ittcsec/ittcsecscan-public
cd ittcsecscan
go build -mod=vendor -o ittcsecscan ./cmd/ittcsecscan
./ittcsecscan version
```

## Verify a downloaded release

Every release carries `SHA256SUMS` (over all binaries and SBOMs) and `SHA256SUMS.sig` (an
OpenSSH signature made offline with the release key, only after an independent byte-for-byte
rebuild matched CI). Verify against the trust root on `main`:

```sh
# from a clone of this repository's main branch (OpenSSH 8.1+, or Git Bash on Windows)
release/verify.sh --partial /path/to/downloaded/folder
```

The release key fingerprint is published in [SECURITY.md](../SECURITY.md); if a fingerprint
you obtain elsewhere ever differs, report it as a security issue.

- **Windows**: run the verify step in Git Bash. Prefer Windows Terminal; the CLI escapes
  untrusted text written to the terminal.
- **macOS**: on first run, clear the quarantine attribute if Gatekeeper blocks the unsigned
  binary (`xattr -d com.apple.quarantine ittcsecscan`), or build from source.

## First run

```sh
ittcsecscan auth plan        # show which providers resolve credentials, read-only
ittcsecscan scan             # collect, analyze, and print findings for the resolved providers
ittcsecscan scan --report-dir ./out   # also write JSON, SARIF, HTML, PDF, and DOCX reports
ittcsecscan doctor           # environment and data-directory safety checks
```

Credentials come from each provider's native chain or the documented environment variables
(see [permission-matrix.md](permission-matrix.md)); ittcsecscan never stores them.
