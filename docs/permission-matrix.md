# Permission matrix

The least-privilege, read-only permissions ittcsecscan needs, per provider and collector,
for the **discovery** profile (a normal scan). Deep-evidence and remediation profiles are
separate and, today, empty except where a reviewed feature requires them.

**Authoritative source.** This table is a human-readable view of the checked-in templates
under [`permissions/`](../permissions). Those JSON templates are embedded in the binary and
**reconciled in CI against the real permission each collector declares in code**, so the
grant list cannot silently drift from what the scanner actually calls. If this document and
the templates ever disagree, the templates win; regenerating this table from them is tracked
as a follow-up (HARDEN-1). Every permission below is read-only; the scanner performs no
write in the discovery profile.

## AWS (IAM actions)

| Collector | Permissions |
|---|---|
| iam.identities | `iam:GetAccountAuthorizationDetails`, `iam:ListAccountAliases` |
| iam.credentialReport | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` |
| s3.buckets | `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketTagging` |
| s3.accessPoints | `s3:ListAccessPoints`, `s3:GetAccessPointPolicy`, `s3:GetAccessPointPolicyStatus`, `ec2:DescribeRegions` |
| ec2.instances | `ec2:DescribeInstances`, `iam:GetInstanceProfile` |
| ec2.network | `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`, `ec2:DescribeInternetGateways`, `ec2:DescribeEgressOnlyInternetGateways`, `ec2:DescribeNatGateways`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkAcls`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeAddresses` |
| ec2.vpcEndpoints | `ec2:DescribeVpcEndpoints` |
| ec2.ebsSnapshots | `ec2:DescribeSnapshots`, `ec2:DescribeSnapshotAttribute` |
| lambda.functions | `lambda:ListFunctions`, `lambda:GetPolicy`, `lambda:ListFunctionUrlConfigs` |
| rds | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBClusterSnapshotAttributes` |
| kms | `kms:ListAliases`, `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:GetKeyRotationStatus`, `kms:ListResourceTags` |
| bedrock.agents | `bedrock:ListAgents`, `bedrock:GetAgent`, `bedrock:ListAgentActionGroups`, `bedrock:GetAgentActionGroup`, `bedrock:ListAgentKnowledgeBases`, `bedrock:ListDataSources`, `bedrock:GetDataSource` |
| logging | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeDeliveryChannels` |
| securityservices | `guardduty:ListDetectors`, `guardduty:GetDetector`, `securityhub:DescribeHub`, `securityhub:GetEnabledStandards`, `access-analyzer:ListAnalyzers`, `inspector2:BatchGetAccountStatus`, `macie2:GetMacieSession` |
| organizations | `organizations:DescribeOrganization`, `organizations:ListRoots`, `organizations:ListOrganizationalUnitsForParent`, `organizations:ListAccountsForParent`, `organizations:ListPolicies`, `organizations:DescribePolicy`, `organizations:ListTargetsForPolicy` |

Every action above is read-only (`Describe`, `Get`, `List`, and the credential-report pair). AWS's
built-in `ReadOnlyAccess` policy covers the whole set; `SecurityAudit` covers the original core set
but not necessarily the newer Bedrock, Lambda, and S3 access-point reads, so grant `ReadOnlyAccess`
(or the per-collector actions above) when using the AI-agent and second-tier collectors.

## Azure (Microsoft Graph scopes and ARM actions)

| Collector | Permissions |
|---|---|
| entra.identities | `Application.Read.All`, `Group.Read.All`, `User.Read.All` (Graph) |
| entra.securityDefaults, entra.conditionalAccess | `Policy.Read.All` (Graph) |
| rbac.assignments | `Microsoft.Authorization/roleAssignments/read`, `.../roleDefinitions/read`, `.../denyAssignments/read` |
| storage.accounts | `Microsoft.Storage/storageAccounts/read` |
| compute.virtualmachines | `Microsoft.Compute/virtualMachines/read` |
| network | `Microsoft.Network/{virtualNetworks,networkSecurityGroups,publicIPAddresses,networkInterfaces}/read` |
| keyvault | `Microsoft.KeyVault/vaults/read` |
| database | `Microsoft.Sql/servers/read`, `Microsoft.DBforPostgreSQL/flexibleServers/read`, `Microsoft.DBforMySQL/flexibleServers/read`, `Microsoft.DocumentDB/databaseAccounts/read` |
| logging | `Microsoft.OperationalInsights/workspaces/read`, `Microsoft.Insights/diagnosticSettings/read` |
| defender | `Microsoft.Security/pricings/read`, `Microsoft.Security/autoProvisioningSettings/read` |
| management.hierarchy | `Microsoft.Management/managementGroups/read` |

Azure's built-in **Reader** role covers the ARM actions; the Graph scopes are granted to the
app registration.

## GCP (IAM permissions)

| Collector | Permissions |
|---|---|
| iam.serviceaccounts | `iam.serviceAccounts.list` |
| iam.serviceAccountKeys | `iam.serviceAccountKeys.list` |
| iam.workloadIdentityFederation | `iam.workloadIdentityPools.list`, `iam.workloadIdentityPoolProviders.list` |
| iam.policy | `resourcemanager.projects.getIamPolicy`, `iam.roles.get`, `iam.denypolicies.list` |
| orgpolicy.effective | `orgpolicy.policies.get` |
| cloudidentity.groupMembers | `resourcemanager.projects.getIamPolicy`, `cloudidentity.groups.get`, `cloudidentity.groups.memberships.list` |
| storage.buckets | `storage.buckets.list`, `storage.buckets.getIamPolicy` |
| compute.instances | `compute.instances.list` |
| compute.network | `compute.{networks,subnetworks,firewalls,routes,routers,addresses,globalAddresses,forwardingRules,globalForwardingRules}.list` |
| cloudsql.instances | `cloudsql.instances.list` |
| cloudkms.cryptokeys | `cloudkms.locations.list`, `cloudkms.keyRings.list`, `cloudkms.cryptoKeys.list` |
| logging | `logging.sinks.list`, `logging.buckets.list` |
| scc.sources | `securitycenter.sources.list` |
| resourcemanager.hierarchy | `resourcemanager.projects.get`, `resourcemanager.folders.get`, `resourcemanager.organizations.get` |

GCP's built-in **roles/viewer** plus **roles/iam.securityReviewer** covers most of this set.

## GitHub (token scopes / fine-grained permissions)

| Collector | Permissions |
|---|---|
| repositories, workflows, artifacts | `metadata:read` |
| workflows, artifacts | `actions:read` |

A fine-grained personal access token with repository **Metadata: read** and **Actions:
read** suffices. `GITHUB_TOKEN` in the environment.

## GitLab (token scopes)

| Collector | Permissions |
|---|---|
| projects, pipelines, artifacts | `read_api` |

A personal access token with the `read_api` scope. `GITLAB_TOKEN` (and, for gitlab.com,
the default host) in the environment.

## Kubernetes (RBAC list verbs)

| Collector | Permissions |
|---|---|
| namespaces | `list namespaces` |
| serviceaccounts | `list serviceaccounts` |
| rbac | `list roles`, `list rolebindings`, `list clusterroles`, `list clusterrolebindings` (rbac.authorization.k8s.io) |

The built-in **view** ClusterRole covers these reads. Authentication is the pod's
in-cluster service account.

## Okta (API token scopes)

| Collector | Permissions |
|---|---|
| users, groups | `okta.users.read` |
| groups | `okta.groups.read` |

A read-only Okta API token (`OKTA_ORG_URL`, `OKTA_API_TOKEN`).

## Google Workspace (OAuth scopes)

| Collector | Permissions |
|---|---|
| users | `admin.directory.user.readonly` |
| groups | `admin.directory.group.readonly`, `admin.directory.group.member.readonly` |

A bearer token for a principal with these read-only Directory scopes
(`GOOGLE_WORKSPACE_TOKEN`).

## MCP

| Collector | Permissions |
|---|---|
| servers | read the local `mcpServers` config file (`MCP_CONFIG_FILE`) |

No remote credential; the collector reads a local file and never emits its secret fields.
