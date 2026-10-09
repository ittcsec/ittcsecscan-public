# Remediation coverage audit (item 7)

Every finding type a scan can produce must ship either a real, apply-ready remediation
(a concrete CLI command and a Terraform snippet, parameterized from the finding's own
identifiers, never prose hints) or a specific, tracked named gap that states why no
apply-ready action exists. A finding type in neither is a build failure: the test
`TestEveryShippedRuleHasRemediationOrNamedGap` (`internal/remediate/coverage_test.go`)
loads every rule in the embedded packs and asserts each is covered, so a newly shipped
detection cannot land without a deliberate remediation decision. `TestTemplatesShipRealCLIAndIaC`
asserts every template emits a real CLI command, a real IaC snippet (at least one a concrete
Terraform `resource` block), and a verification step. Plan generation stays offline and
deterministic: content is authored in code from official provider documentation
(`internal/remediate/catalog.go`), never fetched.

This table is the audit result for the currently shipped finding types (the `core-p0` pack).

## Apply-ready (real CLI command + Terraform snippet)

| Finding type | CLI | Terraform |
|---|---|---|
| CORE-P0-STORAGE-PUBLIC-AWS | `aws s3api delete-bucket-policy` / `put-bucket-acl --acl private` | `aws_s3_bucket_acl` resource (ACL reset); policy removal shown as a guided comment, since deleting a policy is a resource removal, not a settable argument |
| CORE-P0-STORAGE-PUBLIC-AZURE | `az storage account update --allow-blob-public-access false` | `azurerm_storage_account.allow_nested_items_to_be_public = false` |
| CORE-P0-STORAGE-PUBLIC-GCP | `gcloud storage buckets remove-iam-policy-binding` / `update --public-access-prevention=enforced` | `google_storage_bucket.public_access_prevention = "enforced"` |
| CORE-P0-DATABASE-PUBLIC-AWS | `aws rds modify-db-instance --no-publicly-accessible` | `aws_db_instance.publicly_accessible = false` |
| CORE-P0-DATABASE-PUBLIC-AZURE | `az {postgres,mysql} flexible-server update` / `az cosmosdb update` / `az sql server update` (by engine) | engine-specific: `azurerm_postgresql_flexible_server` / `azurerm_mysql_flexible_server` / `azurerm_cosmosdb_account` / `azurerm_mssql_server` (doc-verified arguments) |
| CORE-P0-DATABASE-PUBLIC-GCP | `gcloud sql instances patch --no-assign-ip` / `--clear-authorized-networks` | `google_sql_database_instance.ip_configuration { ipv4_enabled = false }` |
| CORE-P0-KMS-ROTATION-AWS | `aws kms enable-key-rotation` | `aws_kms_key.enable_key_rotation = true` |
| CORE-P0-KMS-ROTATION-GCP | `gcloud kms keys update --rotation-period=...` | `google_kms_crypto_key.rotation_period = "7776000s"` |
| CORE-P0-KEYVAULT-PURGE-AZURE | `az keyvault update --enable-purge-protection true` | `azurerm_key_vault.purge_protection_enabled = true` |

## Named gaps (tracked, no apply-ready action)

| Finding type | Reason |
|---|---|
| CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS | RP-6: the safe fix depends on operator intent (which ports and source ranges must stay open), and the finding records only that the resource is open on all ports, not which rule is the offender. Portal/CLI guidance to restrict the security group is given; no apply-ready plan is generated. |
| CORE-P0-COMPUTE-INTERNET-EXPOSED-AZURE | RP-6 (as above; NSG rule). |
| CORE-P0-COMPUTE-INTERNET-EXPOSED-GCP | RP-6 (as above; firewall rule). |

## Not shipped yet

The ITTCsecAI Guard pack (`ai-guard`, ADR-0033) is built but not embedded (it awaits the
maintainer's pack signature), so its rule ids are not shipped finding types and are not covered
here. When that pack is embedded, `TestEveryShippedRuleHasRemediationOrNamedGap` will require
a real template or a named gap for each of its rules, so it cannot ship without a remediation
decision.

## What this audit found and fixed

The audit surfaced one real gap: `CORE-P0-DATABASE-PUBLIC-AZURE` shipped a CLI command but
no Terraform snippet. Real, doc-verified `azurerm` arguments exist for every engine
(`public_network_access_enabled` for PostgreSQL flexible, Cosmos DB, and SQL; the string
`public_network_access = "Disabled"` for MySQL flexible), so the Terraform snippet was added
rather than the gap being left silent.
