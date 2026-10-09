# Known limitations

An honest, public statement of what ittcsecscan does **not** do yet, so an operator is
never misled about coverage. This complements the residual-risk register in
[threat-model.md](threat-model.md) §6 (which covers security residual risks); this document
covers functional scope gaps. None of these is a correctness defect in what ships: each is
a bounded, named gap, and the scanner represents an ungrounded relationship as absent rather
than guessing it.

## Coverage gaps by domain

- **Endpoint devices (ENDPOINT-1).** The `endpoint_device` node type exists but no collector
  populates it. There is no non-fabricated, dependency-free source available in this
  project's environment; the intended source is an EDR/MDM API (for example Intune managed
  devices over the existing Azure Graph client) once such access exists. It is deliberately
  not fabricated from names or tags.
- **Self-managed GitLab (GL-1).** The GitLab provider targets `gitlab.com`. A self-managed
  host would need a base-URL and OIDC-issuer override, threaded through the client and the
  federation-edge recognizer.
- **Kubernetes workloads and network policies (K8S-2, K8S-3).** The Kubernetes provider
  collects identity and RBAC (namespaces, service accounts, roles, bindings) but not yet
  pods/deployments and their service-account bindings, nor network policies. External
  `kubeconfig` support (K8S-1) is also deferred (it would require a YAML dependency; the
  provider uses in-cluster service-account auth only).
- **Microsoft 365 identity (M365-1).** Covered by the Azure Entra collectors (Microsoft
  Graph users/groups/service principals); not implemented as a separate provider. Any thin
  gap versus a dedicated M365 identity collector is tracked here.
- **App registration to service principal join (AZURE-APPCRED-1).** The app-credential
  collector (ADR-0036) reads each Entra application registration's certificate and client
  secret expiry and emits the application as its own workload node (keyed by the app object
  id, `azure_type=app_registration`), distinct from the service principal the identity
  collector emits (keyed by the service principal object id). Joining the two by their shared
  `appId` so a credential's expiry is visible on the service principal's authorization graph
  is a named follow-up; the `app_id` fact is carried on both sides as the forward key for it.
  The credential value is never read (Graph returns none on a read), and the secret-adjacent
  `hint` field is stripped before evidence.
- **App-role assignment call cost and scope (AZURE-APPROLE-1).** The app-role assignment
  collector (ADR-0036) resolves application permissions by reading each service principal's
  appRoles catalog once and then each principal's appRoleAssignments (one Graph call per
  principal), so on a large tenant the per-principal pass is bounded by the shared call
  budget and the remainder is a recorded Partial gap, never a silent stop. It records the
  permission value as the ground fact and synthesizes no privilege verdict: there is no
  effective-privilege engine for Microsoft Graph application permissions yet (the AWS
  effective-privilege engine does not cover them), so classifying which Graph app permissions
  are high-impact is a named follow-up. A `$batch`ed read to cut the per-principal round trips
  is a noted efficiency follow-up.
- **SaaS depth (SAAS-1, SAAS-2, SAAS-3).** Okta and Google Workspace collect users, groups,
  and memberships, but not yet Okta apps and assignments, Workspace OAuth app grants, or
  admin-role assignments modeled as privilege edges.
- **AI inventory (AI-1, AI-2) — partially resolved for AWS (ADR-0033).** AWS Agents for
  Amazon Bedrock are now collected read-only: real `ai_agent` nodes, their `invokes_tool`
  edges to action-group tools (with code-execution and cross-account facts), and their
  `accesses_data` edges to knowledge-base data sources (an S3 source joins the collected
  bucket; a web source is marked external). The earlier trust-policy recognition (a role
  trusted by the Bedrock/SageMaker service principal) remains and is complementary. Still not
  collected: SageMaker and Bedrock *model* inventory, and the GCP/Azure AI-runtime service
  principals.
  **Live-verification scope (AWS Bedrock):** a live run against the AWS test account
  (425046147213) verified authentication, per-region handling, and gap classification
  (opt-in regions report Unsupported "region not enabled", unreachable regions report Partial,
  and the per-agent services inherit the agent-listing gap). The agent, action-group, and
  knowledge-base **parsing** (the `ai_agent`/`tool`/`data_store` nodes and the
  `invokes_tool`/`accesses_data` edges) is **fixture-only**: the test account contains no
  Bedrock agents, so that mapping is exercised by unit fixtures, not by live data.
- **Bedrock agent version scope (AI-3).** The Bedrock collector reads each agent's `DRAFT`
  (current) configuration. Numbered version snapshots and the aliases that point to them are
  not enumerated, so a deployed alias pinned to an older version is not separately assessed;
  the DRAFT is the current configuration an operator edits. Alias/version enumeration is a
  named refinement.
- **Tool-executor privilege (AI-4).** `AIG-TOOL-UNSAFE` flags an agent's code-execution or
  cross-account tools from the action-group configuration. Judging whether a tool's Lambda
  executor can itself reach sensitive assets or the internet needs the executor's own role
  and network facts (a Lambda collector this project does not have yet); that extension is a
  named gap, not inferred.
- **Excessive-agency privilege (AI-5) — resolved.** `AIG-AGENT-EXCESSIVE-PRIVILEGE` now reads
  `effective_privilege_level`, which `graph.MaterializeEffectivePrivilege` resolves (deny-
  evaluated: attached policies, inline, permission-boundary cap, explicit deny, account SCP
  cap) and writes onto the agent, and requires the `iam.identities` collection; it fires on
  real data, never from a name. **Correction:** as first shipped the rule checked
  `privilege_level` on the role node (AWS writes it on the attached policy, never the role)
  and required `iam.effectivePrivilege` (emitted by no collector), so it could never fire and
  always reported not-assessed; the earlier "auto-lights when Layer A lands" claim was wrong.
  A groundedness guard test now rejects any rule requiring a fact or service nothing produces.
- **Azure and GCP AI agent edges (AI-6).** Azure AI Foundry agents (tools and data
  connections, a project data-plane with preview surface) are a real follow-on source, built
  in a later slice once the stable contract is pinned. GCP Vertex reasoning engines are
  listable for inventory, but per-tool and per-datastore wiring is code-packaged in the
  deployed engine and is not returned as structured control-plane configuration, so those
  edges are a named gap with that reason, not inferred.
- **ai-guard pack activation (AI-7).** The `ai-guard` detection pack is built, committed, and
  tested, but not yet embedded in the binary: a built-in pack must carry a valid manifest
  signature by the offline pack-signing key. Until the maintainer signs `packs/ai-guard/manifest.json`
  and adds the pack to `packs/embed.go`, the Bedrock collector ships live but the three AI
  detections are dormant.
- **Service-account key scope (GCP-SAKEY-1).** The service-account key collector (ADR-0037)
  reads each account's user-managed keys (`iam.serviceAccountKeys.list`) and records each
  key's age, because a long-lived, downloadable user-managed private key is GCP's highest-risk
  standing credential. System-managed keys (Google-held, auto-rotated) are deliberately not
  listed: they are not a rotation risk and carry no downloadable material. The per-account key
  list is one call per service account, bounded by the shared call budget; the remainder of a
  very large project is a recorded Partial gap, never a silent stop. A dormant-key or
  stale-key detection that consumes `key_age_days` is a named follow-up (it rides the same path
  as the AWS dormant-credential work in DORMANT-1).
- **VPC endpoint policy parsing is fixture-only (AWS-VPCE-1).** The VPC endpoint collector
  (ADR-0035) reads each region's endpoints and records the resource policy as a fact plus
  structural observations (default/wildcard-principal/wildcard-action/condition-present), never a
  verdict. Authentication, the full 34-region fan-out, and gap classification are live-verified
  (17 complete, 1 partial, 16 opt-in-not-enabled Unsupported, 0 errored on the test account); the
  policy *parsing* is exercised by unit fixtures only, because the test account has no VPC
  endpoints. Note that the AWS full-access default endpoint policy is itself wildcard-principal
  and unconditional, so `policy_principal_wildcard` alone is not a finding; `policy_default`
  distinguishes the benign default from a customized open policy (a rule's call, AWS-VPCE-2).
- **Workload identity federation parsing is fixture-only; SA-impersonation join pending (GCP-WIF-1).**
  The workload identity federation collector (ADR-0037) lists the project's WIF pools
  (`iam.workloadIdentityPools.list`) and each pool's providers
  (`iam.workloadIdentityPoolProviders.list`), recording each provider's type (OIDC/AWS/SAML), its
  external issuer (OIDC issuer URI or AWS account id), and whether an attribute condition narrows
  the trust (`has_attribute_condition`), with a contains edge from the pool. A provider with no
  attribute condition and a broad issuer lets any external identity from that issuer impersonate a
  service account. Authentication, the permission, and the API are live-verified (both lists
  Complete on the test project); the pool/provider parsing is fixture-only because the test project
  has no WIF pools. Joining a provider to the specific service accounts it may impersonate (the
  `principalSet://.../workloadIdentityPools/...` members in the project IAM policy, collected by the
  IAM policy collector) so the external-to-SA federation edge is drawn is a named follow-up; the
  pool resource name is carried as the forward key for it.
- **S3 access point parsing is fixture-only; region state from real opt-in status (AWS-S3AP-1).**
  The S3 access point collector (ADR-0035) lists each region's access points (`s3:ListAccessPoints`)
  and reads each one's public status (`s3:GetAccessPointPolicyStatus`) and policy
  (`s3:GetAccessPointPolicy`), recording `is_public`, `network_origin` (Internet vs VPC), and the
  policy observation, with a routes_to edge to the bucket node. S3 Control returns a plain
  `AccessDenied` (not a distinct region-not-enabled code) for a region the account has not opted
  into, indistinguishable by error code from a genuine permission denial. Rather than infer region
  state from that ambiguous error, the collector reads the account's **authoritative region opt-in
  status first** (`ec2:DescribeRegions`, AllRegions): a region EC2 reports as `not-opted-in` is
  recorded Unsupported "region not enabled" and S3 Control is not called there, while **in an enabled
  region an `AccessDenied` is a genuine denial and is recorded Denied, never reclassified** (a real
  denial is never masked). If the opt-in read itself fails, the collector falls back to attempting
  every region and classifying each error literally (AccessDenied stays Denied), recorded as the
  `s3.regionOptInStatus` completeness. Live-verified across the full 34-region set; the access-point
  parsing is fixture-only because the test account has no access points.
- **EBS snapshot public-share parsing is fixture-only (AWS-EBS-1).** The EBS snapshot collector
  (ADR-0035) lists each region's own snapshots and reads each one's createVolumePermission to
  record `public_shared` (shared with the "all" group). Authentication, the full 34-region
  fan-out, and gap classification are live-verified (17 complete, 1 partial, 16 opt-in-not-enabled
  Unsupported, 0 errored on the test account); the public-share *parsing* is exercised by unit
  fixtures only, because the test account has no EBS snapshots. A snapshot whose attribute read
  failed is `public_shared=unknown`, never a silent "false".
- **Lambda access parsing is fixture-only (AWS-LAMBDA-1).** The Lambda collector (ADR-0035)
  lists each region's functions and reads each function's URL configs
  (`ListFunctionUrlConfigs`, so an alias URL is not missed) and resource policy
  (`GetPolicy`), recording `public_url` (a URL with AuthType NONE), `resource_policy`
  (open when an Allow statement grants a wildcard principal), and the execution-role
  assumes edge. Environment variable VALUES are stripped structurally (evidence and node
  facts carry only the names), so a secret set in an env var never reaches evidence. This
  capability adds the `aws-sdk-go-v2/service/lambda` module (a genuinely new, vendored
  dependency, same SDK family as the ec2/iam/s3 modules already vendored). Authentication,
  the full 34-region fan-out, and gap classification are live-verified (17 complete, 1
  partial, 16 opt-in-not-enabled Unsupported, 0 errored); the function/URL/policy parsing
  and the env-var strip are exercised by unit fixtures only, because the test account has
  no Lambda functions. Judging whether a function's executor can itself reach sensitive
  assets (the AI-4 tool-executor gap) is still future work; this collector supplies the
  executor's role and public-exposure facts it needs.
- **Effective org policy scope (GCP-ORGPOL-1) — parsing live-verified.** The org-policy collector
  (ADR-0037) reads `projects.policies.getEffectivePolicy` (orgpolicy.policies.get, via
  roles/orgpolicy.policyViewer) for a curated set of documented security boolean constraints
  (service-account key creation/upload, default networks, OS Login, serial-port access, public SQL
  IP, public-access prevention, uniform bucket-level access, automatic default-SA grants), recording
  each constraint's effective enforcement. It is **live-verified** on the test project (all 9
  constraints read and parsed, Complete, 0 unknown, 0 errored). A constraint with no in-force policy
  is `enforced=false` (the documented default, a known state); a constraint whose read failed, whose
  response was unparseable, or whose rule shape this boolean-focused collector does not interpret (a
  list constraint) is `enforced=unknown`, **never `false`** (an undetermined guardrail is never
  rendered as "off", at the node fact and in evidence). **Scope:** the value reported is the
  effective policy AT THE PROJECT, which Google computes server-side by merging any inherited
  organization/folder policy; it is read with project-level `orgpolicy.policies.get`. The collector
  reads this merged value but does not attribute which ancestor set it, because a **project-scoped
  service account cannot read organization- or folder-level policy objects** (that needs
  `orgpolicy.policies.get` at those resources). List-type constraints (for example
  `iam.allowedPolicyMemberDomains`) and a configurable constraint set are named refinements.
- **Azure tenant policy posture (AZURE-SECDEF-1, AZURE-CA-1).** The security defaults collector
  (ADR-0036) reads `/policies/identitySecurityDefaultsEnforcementPolicy` with Policy.Read.All and
  records `security_defaults_enabled`; it is available on every tenant regardless of license and is
  **live-verified** on the test tenant (Complete, enabled=true, real data). The Conditional Access
  collector reads `/identity/conditionalAccess/policies` with the same permission; CA requires an
  Entra ID P1/P2 license, and an unlicensed tenant returns an empty list (or a licensing error).
  Per ADR-0036, **both an empty list and a licensing error are recorded Unsupported, never Complete
  and never a pass** (the scanner never claims "no CA gaps" when it cannot see whether CA applies).
  Live-verified on the test tenant: the unlicensed empty-list path returns Unsupported; the
  CA-policy *parsing* is fixture-only because the tenant returned no policies. OAuth consent grants
  (oauth2PermissionGrants) remain a named gap: their least-privilege read is Directory.Read.All,
  which the maintainer has deliberately not granted, so that capability is not built.
- **Group-member read permission and its live check (GM-PERM-1).** The Entra identity collector's
  group-member read (`GET /groups/{id}/members`) accepts `Group.Read.All` as an application
  permission (Microsoft Graph "List group members", graph-rest-1.0, verified 2026-10-05: the
  Application permissions are `GroupMember.ReadBasic.All` least-privileged and
  `Directory.Read.All, Group.Read.All, Group.ReadBasic.All, Group.ReadWrite.All, GroupMember.Read.All,
  GroupMember.ReadWrite.All` higher-privileged). The collector already requires `Group.Read.All` to
  list groups, so the previously-declared `GroupMember.ReadBasic.All` was redundant and has been
  removed from the requirement and the permission template together. The member read is **not yet
  live-exercised** because the test tenant has zero groups, so the membership pass is a no-op and
  emits no `entra.groupMembers` record; the identity live test now asserts that the first time the
  tenant has a group, `entra.groupMembers` must not be Denied (which would disprove the Group.Read.All
  assumption). Until a group exists, this remains doc-confirmed but not live-confirmed.
- **Credential/role age facts and the role tracking window (AGE-FACTS-1).** For the identity-hygiene
  detections, collectors emit raw numeric age-in-days facts next to the dates they already collect, so
  a rule can threshold them with `fact_num` while the threshold stays in the signed rule (policy is
  never baked into a collector): the AWS credential report emits per active access key
  `cred_access_key_N_age_days` (since creation/rotation), `cred_access_key_N_last_used_age_days`, and
  `cred_access_key_N_never_used`; the IAM role list emits `role_last_used_age_days` and a
  `service_linked` flag (by the `/aws-service-role/` path prefix). A credential-report sentinel
  (`N/A`, `no_information`, `not_supported`) is not a date, so a last-used sentinel sets
  `never_used=true` and emits no last-used age (unknown, never zero). **Role dormancy caveat:** AWS
  tracks role activity only for the trailing 400 days (per Region) and returns no `LastUsedDate`
  outside that window, so `role_last_used=never` means "no activity in the trailing-400-day tracking
  window" (the role may have been used earlier, or never), and a dormancy finding is worded to match.
  These age facts change daily; see AGE-FACTS-2 on change-detection.
- **Age facts and change detection (AGE-FACTS-2) - built.** The later-scan change detector records
  an entity as "changed" when its content hash differs, and that hash covers the entity's
  attributes (`internal/store`). An age-in-days fact changes every day, so any entity carrying one
  (`key_age_days`, `days_until_expiry` today; the credential/role age facts in AGE-FACTS-1) would
  otherwise show as "changed" on every scan, drowning the diff in noise. Fix: the content hash is
  now taken over the stable attribute view (`stableAttributes` in `internal/store/content.go`),
  which drops volatile keys identified by a naming convention (a key ending in `_age_days`, or equal
  to `days_until_expiry`). The full attribute map is still sealed and stored unchanged; only the
  change-detection hash ignores these keys, and the same stable view feeds both the first-scan
  loader and later scans so a value hashes identically however it was written. A change in only a
  volatile fact no longer flips "changed", while a change in a stable fact still does: a key
  rotation moves the stable `cred_access_key_N_last_rotated` date (the age resetting alongside it is
  incidental), a new key or toggled MFA changes a stable flag, and added/removed credentials and
  granted permissions appear as entity/edge appeared/disappeared. Static facts such as
  `credential_lifetime_days` are not volatile and stay in the hash. Covered by
  `TestDiffIgnoresAgeTickDetectsRealChanges` (`internal/store/diff_test.go`).
  One-time re-baseline: `content_hash` is an internal change-detection artifact, not a stored-data
  or report schema field, so changing how it is computed is not a schema change and needs no
  migration (the full attribute map is still sealed and stored; `model.SchemaVersion` is unchanged;
  old databases keep loading). The one visible effect is that on the first later scan run with this
  code, every entity that carries a volatile fact and was last stored by pre-fix code has a
  `content_hash` computed the old way (age included); the new hash differs, so each such entity is
  recorded as "changed" exactly once, then settles. Entities with no volatile fact are unaffected
  (`stableAttributes` returns the map unchanged, so the hash is byte-identical). This is a
  self-correcting diff blip, not data loss, and it fits the additive-only rule because no schema
  field changed.
- **identity-hygiene pack activation (IDH-1).** The `identity-hygiene` detection pack (ten rules:
  AWS user/root MFA, access-key unused and unrotated, root access key, role dormancy; Azure app
  credential expired/expiring and over-long lifetime, high-impact Microsoft Graph permission; GCP
  user-managed key age) is built, committed, and tested. It is now **signed by the offline pack key
  and embedded** (`packs/embed.go` embeds it alongside `core-p0` and `ai-guard`), so a real scan
  loads and evaluates it fail-closed under the key in `packs/keys/allowed_signers`
  (`TestEmbeddedPacksAreSignedAndVerify` enforces that every embedded pack is signed and verifies).
  Numeric thresholds live in the signed rule data (`fact_num` value: 90 days for key unused/unrotated,
  role dormancy and GCP key age; 30 days for Azure expiry; 730 days for Azure credential lifetime) and
  the high-impact allowlist in the signed `fact_in` values, so changing a threshold re-signs a rule,
  never a collector. Each rule declares a per-node honesty gate (`indeterminate`) so a node whose
  deciding fact is missing, a sentinel, or an unresolved permission id is reported Unknown, never pass.
  The compliance mappings for `identity-hygiene` and `ai-guard` are **still not in
  `packs/compliance/mappings.json`**, held pending owner review; the shipped-mapping reconciliation
  test now accepts them (the rule ids are embedded), so they can be added once the maintainer approves them.
- **MCP joins (MCP-1).** Configured MCP servers are inventoried from the local config file;
  joining a server to the AI agent that invokes it needs agent configuration or a live MCP
  handshake and is not done.
- **Dormant-credential signal collected, detection pending (DORMANT-1).** The AWS last-used
  and credential-age signal is now collected: the IAM credential report (per-user and
  per-access-key last-used, key age, MFA, root use) and `role_last_used` from
  `GetAccountAuthorizationDetails` (ADR-0035). This closes the collection half of the
  dormant-privilege gap for AWS IAM users, access keys, and roles. A dormant-privilege
  detection (or an ITTCsecID dormant view) that consumes these facts is not built yet, and
  the equivalent last-used signals for Azure and GCP are not collected; those remain the
  reason the `DormantGapStatus` statement is still shown.
- **KMS rotation with no customer-managed keys (KMS-1).** The KMS rotation rules
  (`CORE-P0-KMS-ROTATION-AWS` and the GCP equivalent) evaluate per collected key node that
  carries a `rotation_enabled` fact. When an account has no KMS keys at all (the AWS test
  account 425046147213: `kms.keys` collected 0 across every region), the rule has no candidate
  node and so produces no finding: not a pass, a fail, or a not-applicable, it simply does not
  appear. Absence of keys is not evidence of posture, so the engine reports nothing rather than
  manufacturing a pass. This is distinct from a per-key not-applicable: an AWS-managed key, for
  which `GetKeyRotationStatus` is unsupported, records `rotation_enabled=not_applicable` (AWS
  manages that key's rotation) and so never produces a false rotation finding. A separate,
  explicit "no KMS keys found" coverage statement is not emitted; the empty result and the
  `kms.keys` coverage row (status complete, collected 0) are the only signal that the account
  has no customer-managed keys.
- **Intermittent store test under -race on Windows CI (STORE-ACQUIRE-FLAKE-1).**
  `TestAcquireFailsLoudlyWhenThePoolIsExhausted` (`internal/store/isolation_test.go`) has failed
  intermittently in the `race detector (windows-2025)` CI job with `context deadline exceeded` at
  the test's first `Acquire`. Investigation finding: this is a **test-timing** flake, not a race in
  the connection pool. The test sets `AcquireWait = 200ms` and `MaxOpen = 1`. `Store.Acquire`, when
  given a deadline-less context, wraps it with `acquireWait` (`internal/store/store.go`), and that
  deadline covers the whole acquire including `openTenant`, which opens the SQLite database and runs
  `verify` (unwrapping the tenant data key through the deliberately CPU-hard KDF). Under `-race`
  (which slows CPU substantially) on a loaded Windows runner, that first-open key derivation can
  legitimately exceed 200ms, so the acquire that should succeed instead times out. Evidence it is
  not a data race: the `-race` job emitted no `DATA RACE` report, only a deadline failure; the test
  passes locally (`-count=3`, without `-race`, which is unavailable locally because it needs cgo);
  and the failing line is the initial setup acquire, not the pool's wait-for-slot path. Per the
  maintainer's instruction it is **not** being fixed by raising the timeout without agreement:
  recorded here as a known intermittent failure. Candidate fixes for the maintainer to weigh (held): do a
  warm-up acquire in the test so the first-open cost is not counted, give this test a larger
  `AcquireWait`, or scope `acquireWait` to the wait-for-slot rather than the connection/KDF setup
  (the last changes production semantics and needs its own review). A re-run of the CI job clears it.
- **Permission-matrix drift check (HARDEN-1).** `docs/permission-matrix.md` is a hand-maintained,
  human-readable view of the checked-in `permissions/*/discovery.json` templates (the authoritative,
  CI-reconciled source). Today nothing enforces that the document and the templates agree: the
  grant lists are kept in sync by hand, so a permission added to a template without a matching doc
  edit (or the reverse) can drift silently, and the document itself states that the templates win on
  any disagreement. Planned fix: make the matrix a generated artifact. Add a generator (for example
  `tools/genpermmatrix`, or a `go test ... -update`) that renders the per-provider tables directly
  from `permissions/*/discovery.json`, grouping each permission under the collector(s) in its
  `enabled_by`, in a fixed deterministic order, and a CI test that regenerates the tables in memory
  and fails if the committed `docs/permission-matrix.md` differs (a golden, `git diff --exit-code`
  style check). Drift then becomes impossible, because the document is the templates rendered, and no
  fragile Markdown parser is needed. This replaces the current hand-written shorthand (the Azure
  `.../roleDefinitions/read` prefix abbreviation and the `Microsoft.Network/{a,b,c}/read` and
  `compute.{a,b,c}.list` brace groups) with generated literal rows; the non-cloud providers, whose
  rows are prose rather than literal permission strings (for example Kubernetes `list:namespaces`
  shown as "list namespaces", or MCP `read:mcp-config` as "read the local config file"), either get
  a small render map or stay in a hand-written preamble the generator leaves untouched. Until then,
  the matrix is kept current by hand (it was last reconciled for v0.2.0-rc.1) and the templates
  remain authoritative.
- **Compliance coverage breadth (PROOF-1, ADR-0034).** ITTCsecProof maps real findings to
  framework controls (NIS2, ISO 27001, GDPR, SOC 2, DORA, CRA), but coverage is only as broad
  as the detection packs. With the shipped `core-p0` rules it references a handful of controls
  per framework; every other control is reported "not assessed", and the view is an
  evidence-coverage map, never a certification or a claim that the tenant "is compliant". The
  mapping references control identifiers only (it does not reproduce framework catalog text)
  and must be maintained as standards change. When part of a control's evidence is unknown it
  is reported "not assessed", never pass, so the layer never overstates coverage.

## Analysis and platform limitations

- **Remediation is plan-only in this release; no shipped command can execute a write against a
  real cloud (RP-12).** The only remediation a user can run is `fix`, which is read-only: it
  generates and prints immutable plans and never changes a cloud. The executor, its drift
  detection, and the immutable per-tenant sealed receipt (Blocker C) exist as internal, tested
  infrastructure behind the experimental `remediation` build tag, but **no shipped command
  reaches them**: even a binary built with that tag has no code path that calls the executor.
  The only write execution ever performed against a live account was through a private test
  harness during development, not through the product. Wiring a real, user-facing apply command
  (the missing caller that would connect `fix` to the executor and the receipt sink) is named
  future work; when it is built, it goes through the same isolated, hold-for-review treatment
  the live S3 write got, with no exception for having done it once already. The receipt system
  is complete at the executor layer so that this caller cannot later be added without producing
  an immutable receipt at verification, but until that caller ships, a real user running
  remediation today produces no receipt because a real user cannot execute a write at all.
- **Zero-egress audit scope (EGRESS-1).** `scan --offline-audit <file>` records every
  outbound connection attempt the tool's shared HTTP clients make (all provider clients and
  the AWS SDK client route their dialer through one audited path), so a user can confirm only
  the scanned provider's endpoints were contacted. It is observational only: it never blocks
  or alters a connection, and it sees the destination host:port, not request contents. It
  captures what the tool dials; it is not a host firewall and does not attest to OS-level
  egress outside the tool's HTTP clients.
- **Configuration exposure, not verified reachability.** Internet-reachability findings are
  computed from configuration (public IPs and allow rules); the scanner never probes, so an
  effective-reachability verdict is always represented as unknown rather than asserted.
- **macOS ACLs.** Filesystem permission checks report `unknown` on macOS rather than `pass`,
  because ACLs cannot be read without cgo (release builds are `CGO_ENABLED=0`).
- **Release provenance (T-07) — RESOLVED.** Releases are reproducible, SBOM-carrying,
  SLSA-provenance-carrying, malware-scanned, offline-signed over checksums, and now carry
  build-time TUF metadata (generated by `release/tuf.sh`; shipped with `v0.1.0-rc.1`). See
  [release/README.md](../release/README.md) and
  [release-rollback-drill.md](release-rollback-drill.md). The remaining TUF items are hosting
  and threshold signing (UP-1) and the online refresh path (UP-8), tracked below, not T-07.
- **Remediation immutable receipt (RP-10) — RESOLVED (Blocker C, PR #166).** The design
  requires remediation to "record an immutable receipt" after
  verification. This is now implemented: migration 0004 adds an append-only, per-tenant
  `remediation_receipts` table, sealed with the tenant data key (like the criticality override
  log), and the executor (`internal/remediate/execute`) records a receipt at every terminal
  outcome, applied or refused, via an injected sink that surfaces any record failure. Mutation-
  and end-to-end-tested. The remaining scope boundary, that no shipped command yet reaches the
  write executor so a real user produces no receipt in practice, is tracked above as **RP-12**,
  not here.
- **Report output location (by design).** Reports written by `scan --report-dir` land in the
  operator-chosen directory (owner-only, 0600), outside the tenant store, because a report is
  a shareable deliverable (threat-model TB5), not tenant state. Its content passes the report
  honesty gate (redaction plus control/bidi neutralization). This is intentional, not a
  storage-scoping gap; the operator controls where it goes.
- **Shared enumeration (EX-6, GL-5).** The three GitHub and three GitLab collectors each list
  repositories/projects independently; sharing that enumeration is a pending efficiency
  follow-up (not a correctness issue).
- **TUF signing is single-key, not threshold (UP-1).** The update metadata format and client
  support a signing threshold per role (ADR-0030), but a single-maintainer project signs each
  role with one offline key, so every role's threshold is 1. Single-key signing does **not**
  meet threshold signing: the compromise or loss of one role key is not contained by other
  signers. It is the same single-trust-anchor limitation as the release signing key
  (threat-model residual item 5). Raising a role's threshold requires a second independent
  key holder; until then, root recovery depends on the offline root-key backup (release
  key custody / UP-7 in [release/README.md](../release/README.md)).
- **Online timestamp/snapshot signing (decided; UP-8 to implement).** The timestamp role
  expires every 24 hours. The decision is **final**: timestamp and snapshot are signed by
  **online automation keys**, root and targets by offline keys only (see the "Online timestamp
  and snapshot keys" section in [release/README.md](../release/README.md)). This removes the
  daily hand-signing single point of failure; the online keys' worst case is withholding or
  replaying within the freeze window, never shipping a malicious target. A missed window still
  **fails closed** (the client returns `ErrExpired` and serves nothing, never stale metadata),
  so the residual risk is availability, not a downgrade. The remaining work (UP-8) is the
  automated snapshot-and-timestamp-only refresh path; until it lands, the interim commitment is
  a fixed daily signing schedule with a named backup signer and an expiry alert.
- **Offline root/targets signing ceremony (UP-7) — performed.** The four offline TUF keys
  (root, targets, snapshot, timestamp) were generated and used to sign the metadata shipped with
  `v0.1.0-rc.1` (`release/tuf.sh`). What remains is client-side wiring, not the ceremony: no
  hosted update endpoint and no pinned root are shipped yet, so `update check` requires both
  `--repo` and `--root` and `internal/update` points nowhere by default (inert by design). That
  wiring is tracked with UP-1 (hosting) and the updater remains inert until it lands.

## Operating posture

- Test tenants only while collectors and remediation mature (the active-validation policy).
- Solo-maintainer review phase (ADR-0008): sensitive changes are owner-reviewed and marked
  for retroactive independent review once a second reviewer exists.
- Remediation writes are experimental, behind a build tag, and require a separate credential
  and an approved, drift-checked plan (ADR-0029).
