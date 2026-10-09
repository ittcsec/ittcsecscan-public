# Command-line reference

Status: active development. `auth`, `doctor`, `help`, `keys`, `scan`, and `version` exist.

```
ittcsecscan <command> [flags]
```

Command output goes to **stdout**. Logs and error messages go to **stderr**, so
stdout stays machine-readable. Every error message is redacted and stripped of
terminal control sequences before printing.

## Commands

### `version`

```
ittcsecscan version [--json]
ittcsecscan --version
```

Prints build identity: version, whether it is a development build, commit,
source-tree state, build time, Go version, and platform. Any field that cannot
be determined is printed as `unknown`. `version` does not read configuration,
so it works even when the configuration is invalid.

`--json` output conforms to `schemas/cli/v1/version.schema.json`.

### `doctor`

```
ittcsecscan doctor [--json] [--strict] [--config FILE] [--log-level L] [--log-format F] [--data-dir DIR]
```

Read-only local health checks. Doctor creates nothing, writes nothing, and
makes no network requests.

| Check ID | Verifies | Statuses |
|---|---|---|
| `runtime.platform` | OS/arch is a release platform | pass, warn |
| `build.identity` | release build from a clean tree | pass, warn |
| `config.load` | configuration loads and validates | pass, fail |
| `config.permissions` | no other account can modify the configuration file, or replace it through any folder above it (others reading it is acceptable: it holds no secrets) | pass, fail, unknown |
| `crypto.sha256` | SHA-256 known-answer test | pass, fail |
| `clock.sanity` | system clock is not earlier than the build time | pass, fail, unknown |
| `filesystem.data_dir` | data directory is determinable and a directory. Fails if other accounts can modify it or replace it through a folder above; warns if they can read it or new files would inherit access (Windows DACLs, Linux mode bits and POSIX ACLs). On macOS, owner-only mode bits give `unknown`, because ACLs are not read | pass, warn, fail, unknown |
| `store.data_keys` | no tenant's data key is near its encryption limit (B-6). Warns at 2²⁷ encryptions (rotate soon), fails at 2²⁸ (the key can no longer seal until rotated). Read-only; counts are read without unwrapping keys and without writing anything | pass, warn, fail, unknown |
| `auth.readiness` | which providers have a credential adapter. Static and makes no network call: it reports only whether an adapter exists, not that access works (that is `auth plan`). A provider with no adapter is `unknown`, never a pass. No adapters are built yet, so this is `unknown` until the authentication adapters are built | pass, unknown |
| `process.privileges` | not running as root/Administrator | pass, warn, unknown |

Overall result: `fail` if any check failed; otherwise `warn` if any check warned
**or was unknown**; otherwise `pass`. Unknown is never counted as a pass.

`--strict` makes warnings and unknowns exit with code 4 as well. `--json` output
conforms to `schemas/cli/v1/doctor.schema.json`.

### `auth`

```
ittcsecscan auth plan [--provider aws|azure|gcp] [--profile discovery|deep-evidence|remediation]
```

Inspect how ittcsecscan authenticates to a cloud provider. Read-only: it never
creates, stores, retrieves, or logs a credential.

`auth plan` resolves the caller's identity for each requested provider (default
all) under a least-privilege profile (default `discovery`) and reports it. It
exits `7` (auth-failed) if **any** requested provider cannot authenticate; an
unknown or denied result is never reported as success. No credential adapters
are built yet, so `auth plan` currently reports auth-failed for every provider;
the AWS, Azure, and GCP adapters arrive with the SDK intake (ADR-0017).

### `keys`

```
ittcsecscan keys init  [--master-key-file FILE] [runtime flags]
ittcsecscan keys check [--master-key-file FILE] [runtime flags]
```

Manages the operator master key that protects all tenant data (ADR-0015).

- `init` creates the master key and writes it, **passphrase-wrapped** (scrypt +
  AES-256-GCM), to the master-key file. It refuses to overwrite an existing key.
  The passphrase is read from the terminal (never echoed, never an argument or an
  environment variable); leaving it empty generates a strong one, shown once. An
  operator-supplied passphrase must be at least 12 characters and is confirmed by
  re-entry.
- `check` reads the master key and confirms the passphrase unwraps it.

There is **no recovery**: if the key file or its passphrase is lost, every tenant
encrypted under it is permanently unreadable. The master-key file holds the path
only, never the key, and must lie outside the data directory. The OS keystore is
a later addition (Windows first); until then this passphrase-wrapped file is the
at-rest protection (B-7).

### `scan`

```
ittcsecscan scan (--tenant ID | --create) [--provider LIST] [--json] [runtime flags]
```

Collects a tenant's cloud graph, **read-only**, and stores it as a sealed,
change-tracked scan. For each provider it authenticates, runs the read-only
collectors, and ingests the result in one transaction.

Exactly one of `--tenant` or `--create` is required. Tenant ids are generated,
never chosen: `--tenant ID` scans an existing tenant, and `--create` makes a new
tenant and prints its id. `--provider` takes a comma-separated list of providers
to scan; the default is every provider that has collectors (today, AWS). A
provider named that has no collectors, or is unknown, is a usage error.

One provider failing to authenticate does not stop the others; its gap is
recorded. The scan never reports a gap as success:

- exit `0` when every provider was covered completely;
- exit `5` (scan-incomplete) when any coverage gap remains: a partial, denied, or
  unsupported enumeration, or a provider that could not authenticate;
- exit `7` (auth-failed) when no provider authenticated at all.

`--budget N` caps the number of provider **collection** calls the whole scan may
make, so its cost is predictable; `0` (the default) is unlimited. The budget is
shared across providers first-come-first-served: when it is exhausted, the
remaining enumerations are recorded as partial (reason: budget exhausted) and the
scan exits 5, never silently skipping them. It counts collection reads only.
**Authenticating to each provider is not counted against the budget**, so `N` is
not the total number of API calls a scan makes: a scan of three providers still
makes its (uncounted) identity call per provider even at `--budget 1`.

**Requested access.** A scan authenticates and reads, never writes. What keeps it
read-only is the permissions you grant the credential (the least-privilege
templates under `permissions/`), not the OAuth scope. This matters on GCP: a GCP
scan requests the broad `https://www.googleapis.com/auth/cloud-platform` OAuth
scope, because Google's `iam.serviceAccounts.list` accepts no read-only-named
scope. The scope is an upper bound on what the token could do; the granted IAM
permissions are the real limit, so grant the scan credential a read-only role and
the broad scope cannot widen it. AWS and Azure have no equivalent scope caveat.
The identity probe (`auth plan`) requests only a narrow identity scope on every
provider.

`--json` output conforms to `schemas/cli/v1/scan.schema.json`.

### `help`

```
ittcsecscan help [command]
ittcsecscan <command> -h
```

## Exit codes

Stable contract (`internal/exitcode`). Codes are only ever added.

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Success |
| 1 | internal | Unexpected failure; also any error without a specific code |
| 2 | usage | Unknown command, bad flag, or unexpected argument |
| 3 | config | Configuration could not be loaded or failed validation |
| 4 | doctor-failed | A doctor check failed (or warned/unknown with `--strict`) |
| 5 | scan-incomplete | Requested scope not fully accounted for (`scan` with any coverage gap) |
| 6 | findings-at-threshold | *Reserved.* Findings at or above the failure threshold |
| 7 | auth-failed | No provider could authenticate: credentials missing, expired, or denied (`auth plan`, `scan`) |
| 8 | integrity-failed | *Reserved.* Signature, digest, or trust-metadata verification failed |
| 130 | interrupted | Cancelled by SIGINT/SIGTERM (Ctrl+C; console close on Windows) |

On the first interrupt, the running command stops at the next cancellation
point and exits 130. A second Ctrl+C terminates immediately.

## Configuration

JSON, validated against `schemas/config/v1/config.schema.json` (ADR-0006).

```json
{
  "schema_version": 1,
  "log": { "level": "info", "format": "text" },
  "data_dir": "/home/alice/.local/share/ittcsecscan"
}
```

| Key | Values | Default |
|---|---|---|
| `schema_version` | `1` (required) | — |
| `log.level` | `debug`, `info`, `warn`, `error` | `info` |
| `log.format` | `text`, `json` | `text` |
| `data_dir` | absolute path | per-user data directory, see below |
| `master_key_file` | absolute path, outside `data_dir` | none (unset) |

Rules: unknown keys, duplicate keys, trailing data, nesting deeper than 32
levels, files over 1 MiB, and non-regular files are all rejected. A UTF-8 BOM is
tolerated. **The file never contains credentials**: cloud access always comes
from the provider's native credential chain.

### Precedence

1. Built-in defaults
2. Configuration file: `--config`, else `ITTCSECSCAN_CONFIG`, else the default
   location if a file exists there
3. Environment: `ITTCSECSCAN_LOG_LEVEL`, `ITTCSECSCAN_LOG_FORMAT`, `ITTCSECSCAN_DATA_DIR`, `ITTCSECSCAN_MASTER_KEY_FILE`
4. Flags: `--log-level`, `--log-format`, `--data-dir`, `--master-key-file`

The configuration is revalidated after each layer, and errors say which layer
introduced the bad value. A file named explicitly (flag or environment) must
exist; the default location is optional.

### Default locations

| Platform | Configuration file | Data directory |
|---|---|---|
| Windows | `%APPDATA%\ittcsecscan\config.json` | `%LOCALAPPDATA%\ittcsecscan` |
| macOS | `~/Library/Application Support/ittcsecscan/config.json` | `~/Library/Application Support/ittcsecscan` |
| Linux and others | `$XDG_CONFIG_HOME/ittcsecscan/config.json` (default `~/.config`) | `$XDG_DATA_HOME/ittcsecscan` (default `~/.local/share`) |

Relative `XDG_*` values are ignored, as the XDG specification requires.

## Logging

Structured `log/slog` on stderr, `text` or `json`. Every record passes through
the redacting handler (`internal/logging`):

- attributes whose key names secret material (`password`, `token`,
  `client_secret`, `authorization`, `session`, …) are replaced by `[REDACTED]`,
  including whole groups;
- messages and string values are scrubbed of recognised credential patterns
  (AWS access key IDs, JWTs, bearer/basic credentials, PEM private keys, URL
  user-info, GitHub/Slack/Google tokens, `key=value` secrets, Azure SAS `sig=`);
- arbitrary structured values are logged only if they are errors or
  `fmt.Stringer`s (scrubbed); anything else is replaced by a type placeholder.
