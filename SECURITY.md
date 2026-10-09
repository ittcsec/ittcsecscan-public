# Security policy

ittcsecscan analyses cloud estates for attack paths. A vulnerability in it can
expose the very credentials, evidence, and attack maps it handles, so we treat
reports seriously.

## Reporting a vulnerability

Do **not** open a public issue, pull request, or discussion.

Email **developer@ittcsec.com** with "ittcsecscan security" in the subject line.
Alternatively, use GitHub's private vulnerability reporting ("Report a
vulnerability" on the repository's Security tab) to open a private advisory.

Please include:

- affected version (`ittcsecscan version --json`) and platform;
- a description of the issue and its impact;
- reproduction steps, using synthetic or test-tenant data only;
- whether the issue is already public.

Never send real customer scan output, credentials, or production identifiers.
Encrypted email is not offered yet. If your report needs sensitive detail,
send a first message without it and ask for a secure channel.

## What to expect

- **Acknowledgement within 7 days** of your report.
- Assessment, fix, and disclosure timelines are agreed with you case by case.
  No other response-time commitment is made at this stage.

## Supported versions

No release has shipped yet. Until 1.0.0, only the latest commit on `main` is
supported. The support window for releases will be published with 1.0.0.

## Scope

In scope:

- the `ittcsecscan` CLI and everything in this repository;
- release artefacts, checksums, SBOMs, and (once implemented) signatures,
  provenance, and update metadata;
- detection and remediation packs published with ittcsecscan.

Especially interesting:

- credential or secret exposure (logs, errors, reports, store, crash output);
- cross-tenant data access;
- code or command execution through scanned resource data, packs, reports, or
  configuration;
- bypass of update verification (rollback, freeze, mix-and-match);
- anything that makes an `unknown` or `error` result appear as a pass;
- remediation executing without an approved plan.

Out of scope: vulnerabilities in the cloud providers themselves (report those to
the provider), findings that require an already-compromised operator account,
and denial of service by the operator against their own machine.

## Safe harbour

If you conduct security research in good faith and in accordance with this
policy, we will not initiate or pursue legal action against you for that
research. Research is in accordance with this policy when you:

- **test only systems you own or are explicitly authorised to test**: your own
  cloud accounts and dedicated test tenants. Never test against production
  customer data or accounts that are not yours;
- **cause no data destruction**: do not delete, corrupt, or modify data, and
  use non-destructive techniques only;
- **commit no privacy violation**: do not access, retain, or share personal
  data or data contents beyond the minimum needed to demonstrate the issue. If
  you encounter such data, stop and report it;
- **cause no service disruption**: no denial-of-service or resource-exhaustion
  testing, and no persistence, payload execution, or credential extraction;
- **report promptly and keep the issue confidential** until disclosure has been
  agreed with us.

These conditions mirror the safeguards ittcsecscan applies to its own active
validation: owned or explicitly authorised systems only, non-destructive probes,
and no persistence, credential extraction, denial of service, or access to data
contents.

This policy covers ittcsecscan only. We cannot authorise testing of third-party
systems, including the AWS, Azure, and Google Cloud platforms you may scan with
it; follow their own security-testing policies. If you are unsure whether an
activity is covered, ask first at the address above.

## Security design

- Safety invariants: the scanner is read-only by default, never stores cloud
  credentials, never reports an unknown or denied result as a pass, and never
  executes remediation without an approved, reviewed plan.
- Dependency policy: [docs/dependency-policy.md](docs/dependency-policy.md).
- Release integrity: [release/README.md](release/README.md). Releases are
  signed offline. Verify them with `release/verify.sh` against
  [release/keys/allowed_signers](release/keys/allowed_signers) from `main`.
  The release key's fingerprint is
  `SHA256:GCFDRVCPT+1rEnF9ax7KhG1TWiyS282ZHGYBKX/BMyM` (Ed25519). If the
  fingerprint in the repository ever differs from one you obtained elsewhere,
  report it as a security issue.
