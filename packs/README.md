# Packs

Built-in detection packs (ADR-0021). Each pack is **declarative data, never code**: a
`manifest.json`, one JSON rule per detection under `rules/`, and fixtures. The engine
(`internal/rules`) evaluates the rules; it never executes pack code, loads plugins, or
gives a rule shell or network access (ADR-0004, ADR-0005).

## Trust

- **External packs** delivered outside the binary are verified in process against an
  OpenSSH signature (`ittcsecscan-pack` namespace, Ed25519) by
  `internal/rules/pack` before any rule is read. An unsigned, tampered, wrong-key, or
  wrong-namespace pack is refused (fail closed).
- **Built-in packs** (this directory, embedded via `packs/embed.go`) are verified against
  the first-party pack-signing key when one is embedded in the trust root
  (`packs/keys/allowed_signers`). When the trust root names a key, `pack.LoadBuiltinAll`
  requires every built-in pack to carry a valid `manifest.json.sig` by that key in the
  `ittcsecscan-pack` namespace, and refuses an unsigned, tampered, wrong-key, or
  wrong-namespace pack (fail closed), exactly like an external pack.
- **Interim (no key embedded yet).** While `packs/keys/allowed_signers` names no key,
  built-in packs are trusted through the binary's own release signature (ADR-0009): they
  are part of the signed artifact and load without a per-pack signature. This is explicit,
  not silent: the moment a key is embedded, verification becomes mandatory.

## `core-p0`

The first P0 detections, grounded in facts the collectors actually collect, cross-cloud
where the facts genuinely compare (ADR-0021 §7):

- **Public object storage** (AWS S3, GCP Cloud Storage, Azure Storage): a bucket or
  account exposed to the public via IAM policy, ACL, or blob-public-access.
- **Public managed database** (AWS RDS, Azure SQL/PostgreSQL/MySQL/Cosmos, GCP Cloud
  SQL): a database reachable from the public internet by configuration.
- **Key management** (AWS KMS / GCP Cloud KMS rotation disabled; Azure Key Vault purge
  protection disabled).

Every rule declares its input contract (the node types and completeness services it
reads); the engine reconciles that against a scan so a denied or unsupported read
becomes an honest `unknown`/`not_applicable`, never a false pass (ADR-0021 §5).

## Not yet built (tracked, named in the ADR, not approximated)

Detections whose logic needs a fact or operator that does not exist yet are deferred,
never approximated: standing high-privilege grants (the role name is the node's name,
not a matchable fact), disabled audit logging where *no* trail exists (a scan-level
absence the per-entity model does not express), effective-permission reachability
See ADR-0021 §7.

## Signing the built-in packs

Turning on per-pack verification for the built-in packs is a one-time owner action, done
offline with the same key custody as the ADR-0009 release key. The verification machinery
ships and is tested; until the key below is embedded, built-in packs run
trusted-by-embedding (see Trust, above).

Steps 1 and 2 are first-time setup only: skip them and start at step 3 if the pack signing key already exists.

1. **Create the offline pack key.** Passphrase-protect it (`-a 100`) and never add it to
   `ssh-agent`. Keep it on removable media with one offline backup in a separate place,
   exactly as for the release key.

   ```sh
   ssh-keygen -t ed25519 -a 100 -C "ittcsecscan-pack" -f ~/.ssh/ittcsecscan_pack_ed25519
   ```

2. **Embed the public key in the trust root.** Append exactly one line to
   `packs/keys/allowed_signers` (the principal and namespace are literal):

   ```sh
   printf 'ittcsecscan-pack namespaces="ittcsecscan-pack" %s ittcsecscan pack signing key\n' \
     "$(cut -d' ' -f1,2 ~/.ssh/ittcsecscan_pack_ed25519.pub)" >> packs/keys/allowed_signers
   ```

3. **Sign every built-in pack's manifest.** `ssh-keygen -Y sign` writes
   `manifest.json.sig` next to each `manifest.json`:

   ```sh
   for dir in packs/*/; do
     [ -f "$dir/manifest.json" ] || continue
     ssh-keygen -Y sign -f ~/.ssh/ittcsecscan_pack_ed25519 -n ittcsecscan-pack "$dir/manifest.json"
   done
   ```

4. **Commit the trust root and every `manifest.json.sig`** through a signed pull request to
   `main`. From then on, `pack.LoadBuiltinAll` requires a valid signature for every built-in
   pack: an unsigned, tampered, wrong-key, or wrong-namespace pack is refused (fail closed).

If a rule file changes, update its SHA-256 digest in that pack's `manifest.json` before
signing (the manifest pins each rule by digest and the signature covers the manifest), then
re-sign the manifest.
