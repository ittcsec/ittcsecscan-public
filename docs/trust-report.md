# ITTCsecProof trust report (shareable, signed, independently verifiable)

A trust report lets a customer hand an auditor, investor, or partner independently
verifiable proof of a scan's results: the report, a detached signature, and the customer's
public key. The recipient verifies the report is authentic and unaltered with this tool or
with stock `ssh-keygen`. There is no server and no hosted portal (the no-server design is
preserved); the three files are self-contained.

It reuses the infrastructure already in the product: the immutable, content-hashed report
model (ADR-0028) and the in-process `sshsig` verifier used for release, pack, and update
signatures (ADR-0009, ADR-0021). Trust reports have their own sshsig namespace,
`ittcsecscan-report`, distinct from the others, so a signature made for one purpose can
never be replayed as another.

## Trust model

Unlike release, pack, and update signing, which verify against a first-party trust root
embedded in the binary, a trust report is signed by the **customer with their own key** and
verified against the **customer's own public key**, which they publish or hand over out of
band. There is no central authority for customer scan results; the recipient trusts the key
the customer gives them, exactly as they would a PGP or SSH identity.

The signing key stays offline and never enters the product: the tool only verifies. This is
the same discipline as release and pack signing, where `ssh-keygen -Y sign` performs the
signature offline and the binary only ever verifies.

## Producing a trust report

1. Scan and write the report:

   ```
   ittcsecscan scan --tenant <id> --report-dir ./out
   ```

   `./out/report.json` is the authoritative, content-hashed model.

2. (Optional) Confirm it is ready to sign and see the exact commands:

   ```
   ittcsecscan trust --report ./out/report.json --attest
   ```

3. Sign those exact bytes offline, with your own key, in the trust-report namespace:

   ```
   ssh-keygen -Y sign -n ittcsecscan-report -f <your-signing-key> ./out/report.json
   ```

   This writes `./out/report.json.sig`.

4. Hand the recipient three files: `report.json`, `report.json.sig`, and your public key
   (`<your-signing-key>.pub`).

## Verifying a trust report

The recipient verifies with this tool:

```
ittcsecscan trust --report report.json --sig report.json.sig --signer <your-signing-key>.pub
```

It is fail closed: it confirms the report's embedded content hash matches its body (the JSON
was not altered after the model was frozen) and that the signature is valid over those exact
bytes in the `ittcsecscan-report` namespace. A tampered report, a wrong key, or a signature
from another namespace is an error, never a pass. On success it prints the tenant, tool
version, scan window, and content hash.

A recipient without this tool can verify with stock OpenSSH and an `allowed_signers` file
listing the customer's key for the `ittcsecscan-report` namespace:

```
ssh-keygen -Y verify -n ittcsecscan-report -s report.json.sig -I <identity> -f allowed_signers < report.json
```

## What verification proves, and what it does not

- It proves the report is **authentic** (signed by the holder of the given key) and
  **unaltered** since it was signed.
- It does **not** attest that the scan was complete or that the environment is secure; the
  report's own coverage-and-blind-spots section and its honest findings state that. A trust
  report makes the report tamper-evident and attributable; it does not change what the report
  says.
