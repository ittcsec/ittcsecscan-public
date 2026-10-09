package remediate

import (
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// content is the template output for one finding type, before it is copied onto
// a plan. Every field is authored from official provider documentation and
// carried in code (never fetched), parameterized only by the entity's real
// identifiers and facts, so plan generation stays deterministic and offline.
type content struct {
	Actions       []model.RemediationAction
	Preconditions []string
	RequiredPriv  []string
	SideEffects   []string
	Verification  []string
	Reversible    bool
	Rollback      []string
}

// computeGapReason is the honest RP-6 statement for the compute-exposure rules,
// which have no apply-ready remediation: the safe fix depends on operator intent
// and the finding does not capture which rule is the offender.
const computeGapReason = "No apply-ready remediation can be generated (RP-6). The safe fix depends on operator intent (which ports and source ranges must remain open), and the finding records only that the resource is open to the internet on all ports, not which rule is the offender. Restrict the security group, NSG, or firewall rule to the required ports and known source ranges after confirming intended use, then re-scan."

// namedGaps are finding types with a specific, tracked reason for having no
// apply-ready action. A rule in neither templates nor namedGaps falls back to a
// generic honest gap; nothing ever fabricates an action.
var namedGaps = map[string]string{ //nolint:gosec // G101: keys are detection-rule ids (some contain "key"/"cred") and values are remediation guidance text, not credentials
	"CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS":   computeGapReason,
	"CORE-P0-COMPUTE-INTERNET-EXPOSED-AZURE": computeGapReason,
	"CORE-P0-COMPUTE-INTERNET-EXPOSED-GCP":   computeGapReason,

	// identity-hygiene and ai-guard are newly embedded. Their findings carry a tracked
	// named gap (apply-ready CLI/IaC remediation templates are pending for both packs; see
	// IDH-1 in docs/known-limitations.md). Each reason states the concrete manual fix and
	// why it is not auto-generated (it depends on operator intent or on interactive,
	// unscopable sign-in), so a finding never falls back to the generic gap.
	"IDH-AWS-IAM-USER-NO-MFA":          "No apply-ready remediation ships yet for this identity-hygiene finding. MFA cannot be enrolled on a user's behalf: the user must register a virtual or hardware MFA device and an admin should enforce an MFA-required policy. An apply-ready guidance template is tracked as pending for the identity-hygiene pack.",
	"IDH-AWS-IAM-KEY-UNUSED":           "No apply-ready remediation ships yet for this identity-hygiene finding. Deactivate then delete the unused access key after confirming no workload depends on it (aws iam update-access-key, then delete-access-key). An apply-ready template is tracked as pending for the identity-hygiene pack.",
	"IDH-AWS-IAM-KEY-UNROTATED":        "No apply-ready remediation ships yet for this identity-hygiene finding. Rotate the access key: create a new key, migrate workloads to it, then deactivate and delete the old key. An apply-ready template is tracked as pending for the identity-hygiene pack.",
	"IDH-AWS-ROOT-KEY-ACTIVE":          "No apply-ready remediation ships yet for this identity-hygiene finding. Delete the root account access keys; the root user should hold no programmatic keys. This requires interactive root sign-in and cannot be automated with a scoped credential. Tracked as pending for the identity-hygiene pack.",
	"IDH-AWS-ROOT-NO-MFA":              "No apply-ready remediation ships yet for this identity-hygiene finding. Enable MFA on the root user; this requires interactive root sign-in and device registration and cannot be automated. An apply-ready guidance template is tracked as pending for the identity-hygiene pack.",
	"IDH-AWS-ROLE-DORMANT":             "No apply-ready remediation ships yet for this identity-hygiene finding. Remove or restrict the dormant role after confirming it is unused across all regions (the 400-day last-used tracking window); deletion depends on operator intent. Tracked as pending for the identity-hygiene pack.",
	"IDH-AZURE-APP-CRED-EXPIRED":       "No apply-ready remediation ships yet for this identity-hygiene finding. Remove the expired application credential and, if the app still needs one, add a fresh short-lived secret or certificate. An apply-ready template is tracked as pending for the identity-hygiene pack.",
	"IDH-AZURE-APP-CRED-LONG-LIFETIME": "No apply-ready remediation ships yet for this identity-hygiene finding. Replace the long-lived credential with a short-lived secret or certificate and shorten the lifetime; the safe window depends on operator intent. Tracked as pending for the identity-hygiene pack.",
	"IDH-AZURE-APP-HIGH-PRIV-GRANT":    "No apply-ready remediation ships yet for this identity-hygiene finding. Revoke or scope down the high-impact Microsoft Graph application permission after confirming it is not required; the safe reduction depends on the app's legitimate use. Tracked as pending for the identity-hygiene pack.",
	"IDH-GCP-SA-KEY-OLD":               "No apply-ready remediation ships yet for this identity-hygiene finding. Rotate or delete the user-managed service account key and prefer keyless workload identity; deletion depends on confirming no workload uses it. Tracked as pending for the identity-hygiene pack.",
	"AIG-AGENT-EXCESSIVE-PRIVILEGE":    "No apply-ready remediation ships yet for ai-guard findings. Scope the agent's granted permissions to least privilege for the tools it actually uses; the safe reduction depends on the agent's legitimate tool set, which the finding does not capture. Tracked as pending for the ai-guard pack.",
	"AIG-TOOL-UNSAFE":                  "No apply-ready remediation ships yet for ai-guard findings. Remove or sandbox the unsafe tool from the agent's toolset, or gate it behind human approval; the correct action depends on whether the tool is intended. Tracked as pending for the ai-guard pack.",
	"AIG-DATA-DANGEROUS":               "No apply-ready remediation ships yet for ai-guard findings. Restrict the agent's access to the sensitive data source or add data-handling controls; the safe scope depends on operator intent. Tracked as pending for the ai-guard pack.",
}

func iac(lines ...string) string { return strings.Join(lines, "\n") }

func resourceName(e model.Entity) string {
	if e.Name != "" {
		return e.Name
	}
	return e.NativeID
}

// azureResourceGroup extracts the resource group from an ARM resource id
// (.../resourceGroups/<rg>/providers/...). It falls back to a visible
// placeholder when the id does not carry one, rather than inventing a value.
func azureResourceGroup(nativeID string) string {
	const key = "/resourcegroups/"
	low := strings.ToLower(nativeID)
	i := strings.Index(low, key)
	if i < 0 {
		return "<resource-group>"
	}
	rest := nativeID[i+len(key):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return "<resource-group>"
	}
	return rest
}

// gcpSegment reads the value following key in a GCP full resource name
// (projects/P/locations/L/keyRings/R/cryptoKeys/K), or a placeholder.
func gcpSegment(nativeID, key, placeholder string) string {
	segs := strings.Split(nativeID, "/")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == key {
			return segs[i+1]
		}
	}
	return placeholder
}

// awsStoragePublic builds guidance for a public S3 bucket that matches exactly what
// the executor does: remove the public mechanism the finding recorded. A public bucket
// policy is deleted (after its text is captured); a public ACL is reset to private
// (after the grants are captured). Block Public Access is deliberately not used here,
// because it would not clear the finding (the scanner reads the policy status and ACL
// grants directly, which BPA leaves in place). When a plan describes a policy deletion
// it is not reversible except from the captured prior policy text.
func awsStoragePublic(e model.Entity) content {
	r := resourceName(e)
	c := content{Reversible: true}
	if e.Attributes["policy_is_public"] == "true" {
		c.Actions = append(c.Actions, model.RemediationAction{
			Provider: model.AWS, Service: "s3",
			Summary: "Delete the public bucket policy so the bucket is no longer public.",
			PortalSteps: []string{
				"Open the S3 console and select bucket " + r + ".",
				"On the Permissions tab, under Bucket policy, choose Edit, then Delete, and confirm.",
			},
			CLI: []string{"aws s3api delete-bucket-policy --bucket " + r},
			IaC: iac(
				`# Remove the public statement from the bucket policy, or delete the`,
				`# aws_s3_bucket_policy resource if it only granted public access.`,
			),
			Privilege: []string{"s3:GetBucketPolicy", "s3:DeleteBucketPolicy"},
		})
		c.Reversible = false // a deletion; restore only from the captured prior policy text
		c.Preconditions = append(c.Preconditions, "The current bucket policy is captured to the remediation receipt before deletion, so it can be recreated if the deletion was a mistake.")
		c.RequiredPriv = append(c.RequiredPriv, "s3:GetBucketPolicy", "s3:DeleteBucketPolicy")
		c.SideEffects = append(c.SideEffects, "The entire bucket policy is deleted, not only its public statement. If the policy also granted non-public access, recreate that from the captured policy.")
		c.Verification = append(c.Verification, "aws s3api get-bucket-policy-status --bucket "+r+" returns NoSuchBucketPolicy or IsPublic false.")
		c.Rollback = append(c.Rollback, "Recreate the bucket policy with aws s3api put-bucket-policy from the prior policy text captured in the remediation receipt; there is no automatic restore.")
	}
	if e.Attributes["acl_all_users"] != "" {
		c.Actions = append(c.Actions, model.RemediationAction{
			Provider: model.AWS, Service: "s3",
			Summary: "Reset the bucket ACL to private so the public grant is removed.",
			PortalSteps: []string{
				"Open the S3 console and select bucket " + r + ".",
				"On the Permissions tab, under Access control list (ACL), choose Edit.",
				"Remove the Everyone (public access) grants, then Save changes.",
			},
			CLI: []string{"aws s3api put-bucket-acl --bucket " + r + " --acl private"},
			IaC: iac(
				`resource "aws_s3_bucket_acl" "this" {`,
				`  bucket = "`+r+`"`,
				`  acl    = "private"`,
				`}`,
			),
			Privilege: []string{"s3:GetBucketAcl", "s3:PutBucketAcl"},
		})
		c.Preconditions = append(c.Preconditions, "The current ACL grants are captured to the remediation receipt before the reset.")
		c.RequiredPriv = append(c.RequiredPriv, "s3:GetBucketAcl", "s3:PutBucketAcl")
		c.SideEffects = append(c.SideEffects, "All non-owner ACL grants are removed; re-add any legitimate non-public grant afterward from the captured ACL.")
		c.Verification = append(c.Verification, "aws s3api get-bucket-acl --bucket "+r+" shows no AllUsers or AllAuthenticatedUsers grant.")
		c.Rollback = append(c.Rollback, "Re-apply a prior non-public grant from the captured ACL in the receipt if one is still needed.")
	}
	if len(c.Actions) == 0 {
		// Flagged public but the offending mechanism is not recorded (RP-7): describe
		// the principle without guessing a concrete action.
		c.Actions = append(c.Actions, model.RemediationAction{
			Provider: model.AWS, Service: "s3",
			Summary: "Remove the public grant (a public bucket policy or a public ACL) that makes " + r + " public. The specific offending grant is not recorded on this finding (RP-7).",
		})
	}
	c.Verification = append(c.Verification, "Re-run the scan; the finding clears.")
	return c
}

// templates maps a rule id to its doc-verified remediation builder. Only finding
// types with a single, unambiguous corrective action appear here (ADR-0029
// section 2); the rest are honest named gaps.
var templates = map[string]func(e model.Entity) content{
	"CORE-P0-STORAGE-PUBLIC-AWS": func(e model.Entity) content {
		return awsStoragePublic(e)
	},

	"CORE-P0-STORAGE-PUBLIC-AZURE": func(e model.Entity) content {
		r, rg := resourceName(e), azureResourceGroup(e.NativeID)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.Azure, Service: "storage",
				Summary: "Disallow blob public (anonymous) access at the storage account level.",
				PortalSteps: []string{
					"Open the storage account " + r + " in the Azure portal.",
					"Under Settings, open Configuration.",
					"Set Allow Blob anonymous access to Disabled, then Save.",
				},
				CLI: []string{
					"az storage account update --name " + r + " --resource-group " + rg + " --allow-blob-public-access false",
				},
				IaC: iac(
					`resource "azurerm_storage_account" "this" {`,
					`  # ...`,
					`  allow_nested_items_to_be_public = false`,
					`}`,
				),
				Privilege: []string{"Microsoft.Storage/storageAccounts/write"},
			}},
			Preconditions: []string{"Confirm no container in this account is intentionally serving anonymous content."},
			RequiredPriv:  []string{"Microsoft.Storage/storageAccounts/write"},
			SideEffects:   []string{"Anonymous access to every container in the account stops; move genuinely public content behind a SAS token or CDN first."},
			Verification:  []string{"az storage account show --name " + r + " --resource-group " + rg + " --query allowBlobPublicAccess returns false.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"Set --allow-blob-public-access true to restore the prior setting."},
		}
	},

	"CORE-P0-STORAGE-PUBLIC-GCP": func(e model.Entity) content {
		r := resourceName(e)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.GCP, Service: "storage",
				Summary: "Remove public IAM members and enforce public access prevention on the bucket.",
				PortalSteps: []string{
					"Open bucket " + r + " in the Cloud Storage console.",
					"On the Permissions tab, remove the allUsers and allAuthenticatedUsers principals.",
					"Set Public access prevention to Enforced.",
				},
				CLI: []string{
					"gcloud storage buckets remove-iam-policy-binding gs://" + r + " --member=allUsers --role=roles/storage.objectViewer",
					"gcloud storage buckets remove-iam-policy-binding gs://" + r + " --member=allAuthenticatedUsers --role=roles/storage.objectViewer",
					"gcloud storage buckets update gs://" + r + " --public-access-prevention=enforced",
				},
				IaC: iac(
					`resource "google_storage_bucket" "this" {`,
					`  # ...`,
					`  public_access_prevention = "enforced"`,
					`}`,
				),
				Privilege: []string{"storage.buckets.setIamPolicy", "storage.buckets.update"},
			}},
			Preconditions: []string{"Confirm no legitimate consumer relies on anonymous access to this bucket.", "Remove any additional public roles beyond objectViewer that appear in the policy."},
			RequiredPriv:  []string{"storage.buckets.setIamPolicy", "storage.buckets.update"},
			SideEffects:   []string{"Anonymous and all-authenticated access to the bucket stops; enforcement can take up to 10 minutes to fully apply."},
			Verification:  []string{"gcloud storage buckets get-iam-policy gs://" + r + " shows no allUsers or allAuthenticatedUsers member.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"gcloud storage buckets update gs://" + r + " --public-access-prevention=inherited relaxes prevention; re-adding public members would restore public access."},
		}
	},

	"CORE-P0-DATABASE-PUBLIC-AWS": func(e model.Entity) content {
		r := resourceName(e)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.AWS, Service: "rds",
				Summary: "Turn off public accessibility on the RDS instance so its endpoint resolves only inside the VPC.",
				PortalSteps: []string{
					"Open the RDS console and select database " + r + ".",
					"Choose Modify, then under Connectivity open Additional configuration.",
					"Set Public access to Not publicly accessible, choose Continue, then Apply.",
				},
				CLI: []string{
					"aws rds modify-db-instance --db-instance-identifier " + r + " --no-publicly-accessible --apply-immediately",
				},
				IaC: iac(
					`resource "aws_db_instance" "this" {`,
					`  # ...`,
					`  publicly_accessible = false`,
					`}`,
				),
				Privilege: []string{"rds:ModifyDBInstance"},
			}},
			Preconditions: []string{"Confirm all clients reach the database from inside the VPC or over a private path before removing public access."},
			RequiredPriv:  []string{"rds:ModifyDBInstance"},
			SideEffects:   []string{"Existing connections over the public endpoint break; --apply-immediately may cause a brief availability impact."},
			Verification:  []string{"aws rds describe-db-instances --db-instance-identifier " + r + " --query 'DBInstances[0].PubliclyAccessible' returns false.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"aws rds modify-db-instance --db-instance-identifier " + r + " --publicly-accessible --apply-immediately restores the prior setting."},
		}
	},

	"CORE-P0-DATABASE-PUBLIC-AZURE": func(e model.Entity) content {
		r, rg := resourceName(e), azureResourceGroup(e.NativeID)
		engine := e.Attributes["engine"]
		var cli []string
		var priv []string
		var iacBlock string
		switch engine {
		case "postgresql":
			cli = []string{"az postgres flexible-server update --resource-group " + rg + " --name " + r + " --public-access Disabled"}
			priv = []string{"Microsoft.DBforPostgreSQL/flexibleServers/write"}
			iacBlock = iac(
				`resource "azurerm_postgresql_flexible_server" "this" {`,
				`  # ...`,
				`  public_network_access_enabled = false`,
				`}`,
			)
		case "mysql":
			cli = []string{"az mysql flexible-server update --resource-group " + rg + " --name " + r + " --public-access Disabled"}
			priv = []string{"Microsoft.DBforMySQL/flexibleServers/write"}
			iacBlock = iac(
				`resource "azurerm_mysql_flexible_server" "this" {`,
				`  # ...`,
				`  public_network_access = "Disabled"`,
				`}`,
			)
		case "cosmosdb":
			cli = []string{"az cosmosdb update --resource-group " + rg + " --name " + r + " --public-network-access Disabled"}
			priv = []string{"Microsoft.DocumentDB/databaseAccounts/write"}
			iacBlock = iac(
				`resource "azurerm_cosmosdb_account" "this" {`,
				`  # ...`,
				`  public_network_access_enabled = false`,
				`}`,
			)
		default: // sql
			cli = []string{"az sql server update --resource-group " + rg + " --name " + r + " --public-network-access Disabled"}
			priv = []string{"Microsoft.Sql/servers/write"}
			iacBlock = iac(
				`resource "azurerm_mssql_server" "this" {`,
				`  # ...`,
				`  public_network_access_enabled = false`,
				`}`,
			)
		}
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.Azure, Service: "database",
				Summary: "Disable public network access on the managed database so only private connections are allowed.",
				PortalSteps: []string{
					"Open database resource " + r + " in the Azure portal.",
					"Open Networking (or Connectivity).",
					"Set Public network access to Disabled, then Save.",
				},
				CLI:       cli,
				IaC:       iacBlock,
				Privilege: priv,
			}},
			Preconditions: []string{"Ensure a private endpoint or VNet path is configured before disabling public access, or clients will lose connectivity."},
			RequiredPriv:  priv,
			SideEffects:   []string{"All connections over the public endpoint are denied once disabled."},
			Verification:  []string{"Re-read the resource; public network access reports Disabled.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"Re-run the same command with the enabled value to restore public network access."},
		}
	},

	"CORE-P0-DATABASE-PUBLIC-GCP": func(e model.Entity) content {
		r := resourceName(e)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.GCP, Service: "cloudsql",
				Summary: "Remove the public IP and the open authorized network from the Cloud SQL instance.",
				PortalSteps: []string{
					"Open Cloud SQL instance " + r + " in the console.",
					"Open Connections, then the Networking tab.",
					"Clear Public IP (or remove the 0.0.0.0/0 authorized network), then Save.",
				},
				CLI: []string{
					"gcloud sql instances patch " + r + " --no-assign-ip",
					"gcloud sql instances patch " + r + " --clear-authorized-networks",
				},
				IaC: iac(
					`resource "google_sql_database_instance" "this" {`,
					`  settings {`,
					`    ip_configuration {`,
					`      ipv4_enabled = false`,
					`      # do not list 0.0.0.0/0 in authorized_networks`,
					`    }`,
					`  }`,
					`}`,
				),
				Privilege: []string{"cloudsql.instances.update"},
			}},
			Preconditions: []string{"Confirm clients connect through the Cloud SQL Auth Proxy or a private path before removing the public IP."},
			RequiredPriv:  []string{"cloudsql.instances.update"},
			SideEffects:   []string{"Connections over the public IP break; --no-assign-ip removes the public address."},
			Verification:  []string{"gcloud sql instances describe " + r + " shows no PRIMARY public address and no 0.0.0.0/0 authorized network.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"gcloud sql instances patch " + r + " --assign-ip restores a public IP if genuinely required."},
		}
	},

	"CORE-P0-KMS-ROTATION-AWS": func(e model.Entity) content {
		r := resourceName(e)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.AWS, Service: "kms",
				Summary: "Enable automatic annual rotation on the customer managed KMS key.",
				PortalSteps: []string{
					"Open the KMS console and select customer managed key " + r + ".",
					"On the Key rotation tab, choose Edit.",
					"Enable Automatically rotate this KMS key, then Save.",
				},
				CLI: []string{
					"aws kms enable-key-rotation --key-id " + r,
				},
				IaC: iac(
					`resource "aws_kms_key" "this" {`,
					`  # ...`,
					`  enable_key_rotation = true`,
					`}`,
				),
				Privilege: []string{"kms:EnableKeyRotation"},
			}},
			Preconditions: []string{"Applies to symmetric customer managed keys; imported key material and asymmetric keys do not support automatic rotation."},
			RequiredPriv:  []string{"kms:EnableKeyRotation"},
			SideEffects:   []string{"None material: prior key versions remain usable to decrypt existing data; new material is used going forward."},
			Verification:  []string{"aws kms get-key-rotation-status --key-id " + r + " returns KeyRotationEnabled true.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"aws kms disable-key-rotation --key-id " + r + " turns rotation off again."},
		}
	},

	"CORE-P0-KMS-ROTATION-GCP": func(e model.Entity) content {
		key := gcpSegment(e.NativeID, "cryptoKeys", resourceName(e))
		kr := gcpSegment(e.NativeID, "keyRings", "<keyring>")
		loc := gcpSegment(e.NativeID, "locations", "<location>")
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.GCP, Service: "kms",
				Summary: "Set a rotation period on the Cloud KMS key so new key versions are generated automatically.",
				PortalSteps: []string{
					"Open Key Management in the console and select key " + key + " in key ring " + kr + ".",
					"Edit the key and set a rotation period (for example 90 days) and a next rotation time.",
					"Save the change.",
				},
				CLI: []string{
					"gcloud kms keys update " + key + " --keyring=" + kr + " --location=" + loc + " --rotation-period=7776000s --next-rotation-time=<next-rotation-time>",
				},
				IaC: iac(
					`resource "google_kms_crypto_key" "this" {`,
					`  # ...`,
					`  rotation_period = "7776000s"`,
					`}`,
				),
				Privilege: []string{"cloudkms.cryptoKeys.update"},
			}},
			Preconditions: []string{"Applies to symmetric encryption keys; asymmetric keys do not support automatic rotation.", "Set <next-rotation-time> to a future RFC3339 timestamp when running the command (a plan is generated without a wall clock)."},
			RequiredPriv:  []string{"cloudkms.cryptoKeys.update"},
			SideEffects:   []string{"None material: existing key versions remain enabled to decrypt existing data."},
			Verification:  []string{"gcloud kms keys describe " + key + " --keyring=" + kr + " --location=" + loc + " shows a rotationPeriod and nextRotationTime.", "Re-run the scan; the finding clears."},
			Reversible:    true,
			Rollback:      []string{"gcloud kms keys update " + key + " --keyring=" + kr + " --location=" + loc + " --remove-rotation-schedule stops automatic rotation."},
		}
	},

	"CORE-P0-KEYVAULT-PURGE-AZURE": func(e model.Entity) content {
		r, rg := resourceName(e), azureResourceGroup(e.NativeID)
		return content{
			Actions: []model.RemediationAction{{
				Provider: model.Azure, Service: "keyvault",
				Summary: "Enable purge protection on the key vault so soft-deleted secrets and keys cannot be permanently purged before their retention expires.",
				PortalSteps: []string{
					"Open key vault " + r + " in the Azure portal.",
					"Under Settings, open Properties.",
					"Set Purge protection to Enabled, then Save.",
				},
				CLI: []string{
					"az keyvault update --name " + r + " --resource-group " + rg + " --enable-purge-protection true",
				},
				IaC: iac(
					`resource "azurerm_key_vault" "this" {`,
					`  # ...`,
					`  purge_protection_enabled = true`,
					`}`,
				),
				Privilege: []string{"Microsoft.KeyVault/vaults/write"},
			}},
			Preconditions: []string{"Purge protection is a one-way setting: once enabled it cannot be disabled for the life of the vault. Confirm this is intended before applying."},
			RequiredPriv:  []string{"Microsoft.KeyVault/vaults/write"},
			SideEffects:   []string{"Soft-deleted vault objects can no longer be purged early and must wait out the retention period.", "This change is permanent and cannot be undone."},
			Verification:  []string{"az keyvault show --name " + r + " --resource-group " + rg + " --query properties.enablePurgeProtection returns true.", "Re-run the scan; the finding clears."},
			Reversible:    false,
			Rollback:      []string{"None. Purge protection cannot be disabled once enabled; there is no rollback for this change."},
		}
	},
}
