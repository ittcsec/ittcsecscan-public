# Coverage matrix

What ittcsecscan collects, per provider and domain, and how each provider's path was
verified. This is a public, honest statement of scope: it distinguishes what is
**live-verified** against a real account from what is **fixture-only** (implemented and
unit-tested against recorded API shapes, but not yet exercised against a live tenant in
this project's environment). It never claims coverage the code does not have.

Ground truth is the code: each collector declares its permissions (see
[permission-matrix.md](permission-matrix.md)), records `Completeness` for every read, and
emits only the provider-neutral nodes and edges listed here. A denied, throttled,
unsupported, or errored read is always a represented gap, never a silent pass.

## Providers

| Provider | Domains collected | Node types | Edge types | Verification |
|---|---|---|---|---|
| **AWS** | Organizations, IAM/identity, IAM credential report (credential/access-key/role age, MFA, root use), networking, VPC endpoint policies, compute, EBS snapshot public exposure, S3, S3 access points, Lambda (function URLs and resource policies), RDS, KMS, Bedrock AI agents, logging (CloudTrail/Config), security services (GuardDuty/SecurityHub/Access Analyzer/Inspector/Macie) | account, organization, identity, role, policy, service, ai_agent, workload, compute, network, data_store, secret_store | assumes, member_of, exposed_to, federates_with, contains | **Live-verified** (against a dedicated AWS test account; example id `123456789012`) |
| **Azure** | Entra identity + group membership, RBAC, security defaults, Conditional Access, storage, compute, networking, Key Vault, databases (SQL/PostgreSQL/MySQL/Cosmos), app credential lifetime, logging, Defender, management groups | subscription, organization, identity, group, role, workload, compute, network, data_store, secret_store | assumes, member_of, exposed_to, contains | **Live-verified** (against a dedicated Entra test tenant; example id `00000000-0000-0000-0000-000000000000`; Graph scopes, ARM may be denied) |
| **GCP** | IAM service accounts + service-account keys + policy + deny policies, workload identity federation, Cloud Identity groups, storage, compute, networking, Cloud SQL, Cloud KMS, logging, effective org policy, Security Command Center, resource hierarchy | project, organization, identity, group, role, workload, compute, network, data_store, secret_store | assumes, member_of, exposed_to, contains | **Live-verified** (against a dedicated GCP test project; example id `example-project`; some APIs disabled report Unsupported) |
| **GitHub** | repositories, workflows (pipelines), build artifacts | repository, pipeline, artifact | contains, builds, federates_with | **Live-verified** (real org: 12 repos, 2 pipelines, 0 artifacts honest-empty) |
| **GitLab** | projects, pipelines (from `ci_config_path`), job artifacts | repository, pipeline, artifact | contains, builds, federates_with | **Fixture-only** (no live GitLab access here; maintainer-runnable live test) |
| **Kubernetes** | namespaces, service accounts, RBAC roles and bindings | cluster, namespace, identity, group, role | contains, assumes | **Fixture-only** (no live cluster; in-cluster live test skips) |
| **Okta** | users, groups, group memberships | identity, group | member_of | **Fixture-only** (no live Okta access here) |
| **Google Workspace** | users, groups, group memberships (incl. nested) | identity, group | member_of | **Fixture-only** (no live Workspace access here) |
| **AI agents (in AWS)** | AI-runtime service principals (Bedrock, SageMaker) trusted by a role | ai_agent | assumes | **Live-exercisable** (AWS; honest-empty when no such role exists) |
| **MCP** | configured MCP servers from the local `mcpServers` config file | mcp_server | (none; standalone inventory) | **Fixture-only** (no configured file here) |

## Cross-domain joins

These edges connect one provider's graph to another's, always by native id from real,
signed/collected data (never a name or tag heuristic):

- **GitHub/GitLab repository -> AWS role** (`federates_with`): derived from an IAM role
  trust policy that federates to the GitHub Actions or GitLab OIDC provider and names the
  repository/project in its `sub` condition. Completes repository -> pipeline -> artifact
  -> workload.
- **AI runtime -> AWS role** (`assumes`): a role trusted by the Bedrock or SageMaker
  service principal.
- **Kubernetes subject -> role** (`assumes`) and **service account -> namespace ->
  cluster** (`contains`).

## Remediation scope

Remediation in this release is **plan-only**. The `fix` command generates and prints immutable,
doc-verified remediation plans and never changes a cloud. Write execution is **out of scope for
this release**: the executor, drift detection, and the immutable per-tenant sealed receipt are
built and tested as internal infrastructure behind the experimental `remediation` build tag, but
no shipped command reaches them, so no user-facing path can mutate a real account. A live write
was performed only through a private development test harness, never through the product. See
[known-limitations.md](known-limitations.md) (RP-12) for the full statement and the named future
work to add a user-facing apply command under isolated review.

## Microsoft 365

M365 identity (users, groups, service principals) is Microsoft Graph, already collected by
the Azure Entra collectors; it is not implemented as a separate provider (see
[known-limitations.md](known-limitations.md), M365-1).

## Not yet collected

See [known-limitations.md](known-limitations.md) for the full list, including endpoint
devices (no non-fabricated source in this environment), self-managed GitLab hosts,
Kubernetes workloads and network policies, and provider-native AI model/agent inventories.
