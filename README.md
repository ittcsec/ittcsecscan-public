# ittcsecscan

ittcsecscan finds real security problems in your cloud, connects them into attack paths, ranks
what matters, and explains how to fix each one. It runs on your own machine, reads only, and keeps
everything it collects local.

## What it does

- **Finds real problems**, like storage open to the public, databases reachable from the internet,
  and encryption keys without rotation.
- **Connects the dots**: it shows attack paths, how one weakness plus an identity can reach
  something sensitive, not just a flat list of issues.
- **Ranks what matters** so you fix the most dangerous things first.
- **Explains the fix** for each finding, with exact steps, and never changes your cloud on its own.
- **Is honest**: if it could not check something (for example, access was denied), it says so. It
  never guesses, and never reports a guess as a fact.
- **Keeps your data local**: everything it collects is stored, encrypted, on your machine. Nothing
  is sent to any server.

## Supported clouds and the read-only guarantee

ittcsecscan scans **AWS, Microsoft Azure, and Google Cloud**. It uses your cloud's own login (the
same one the official CLI uses) and only ever **reads**. It never asks for or stores your cloud
password, and it performs no write, change, or delete in a normal scan. Read-only, least-privilege
permission lists are published per provider in the project's permission matrix.

## What it checks

Alongside the core exposure checks (public storage, public databases, internet-exposed compute,
missing key rotation, and Key Vault without purge protection), it checks:

- **Identity hygiene**: AWS users and the root account without MFA, access keys that are unused or
  never rotated, an active root access key, dormant roles, Azure application credentials that are
  expired or valid for too long, high-impact Microsoft Graph permissions granted to an app, and
  Google Cloud service-account keys that are too old.
- **AI Guard**: risky AI agent setups, an agent with excessive privileges, an unsafe tool, or
  access to dangerous data.

Each check applies to the cloud it is written for. A rule for a cloud you did **not** scan is
reported as **not applicable**, never as a pass, so the report never implies something was checked
when it was not.

## Download

Download the one file that matches your computer from the project's **Releases** page:

| Your computer | File |
|---|---|
| Windows (most) | `ittcsecscan_<version>_windows_amd64.exe` |
| Windows (Arm) | `ittcsecscan_<version>_windows_arm64.exe` |
| Mac (Apple silicon) | `ittcsecscan_<version>_darwin_arm64` |
| Mac (Intel) | `ittcsecscan_<version>_darwin_amd64` |
| Linux (most) | `ittcsecscan_<version>_linux_amd64` |
| Linux (Arm) | `ittcsecscan_<version>_linux_arm64` |

You do not need to install anything else or build the tool yourself.

## Verify your download

Each release is signed. Put the file you downloaded, plus `SHA256SUMS` and `SHA256SUMS.sig` from the
same release, in one folder. From a clone of this repository (OpenSSH 8.1 or later; Git Bash on
Windows), run:

```bash
release/verify.sh --partial FOLDER
```

It checks the signature against the trust root in the repository, then checks every file you
downloaded against `SHA256SUMS`. If it does not print success, do not run the binary.

## Your first scan

1. **Create your local key** (one time). It encrypts everything stored on your machine:

```bash
./ittcsecscan keys init
```

2. **Scan** a cloud you are logged in to, and create a new local record for it:

```bash
./ittcsecscan scan --create
```

It prints a tenant id and writes an encrypted record on your machine.

3. **Get the report**. A report folder is written next to the binary in several formats (HTML,
   JSON, SARIF, PDF, and Word). Open the HTML file in your browser:

```bash
./ittcsecscan scan --create --report-dir ./ittcsecscan-report
```

Every report starts with what was and was not checked, then lists findings worst first, each with
why it matters and how to fix it. Use the tenant id with other commands (for example `fix` to see
remediation steps, or `classify` to mark business-critical assets) to work with the same record
again.

## Honest limitations

- **This is a release candidate.** Interfaces and output may still change before 1.0.0.
- **Remediation is plan-only.** The `fix` command prints exact, documented remediation steps and
  verification guidance. It never changes your cloud. You apply changes yourself.
- **Rules for a cloud you did not scan report "not applicable".** If you scan only AWS, the Azure
  and Google Cloud rules are reported as not applicable rather than as passes.
- **Honest gaps.** When access is denied, a service is unavailable, or data cannot be fully read,
  the result is reported as a gap or as unknown, never as a pass.

## Reporting a security problem

Please do not open a public issue for a security problem. Report it privately through the project's
security policy (`SECURITY.md`), which lists the contact address and what to include. Use synthetic
or test-tenant data only in any report.

## License

Apache-2.0. See [LICENSE](LICENSE).
