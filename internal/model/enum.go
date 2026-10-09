package model

import "slices"

// The canonical enumerations. Each is a typed string with a fixed vocabulary
// and a Valid method. The store maps these strings to the integer codes of
// internal/store/codes.go; the two vocabularies are kept in step by a store
// test. A vocabulary only ever grows at the end, and a name is never reused.

func in[T ~string](v T, set []T) bool { return slices.Contains(set, v) }

// Provider is a supported cloud provider (the required first domains).
type Provider string

const (
	AWS             Provider = "aws"
	Azure           Provider = "azure"
	GCP             Provider = "gcp"
	GitHub          Provider = "github"
	GitLab          Provider = "gitlab"
	Kubernetes      Provider = "kubernetes"
	Okta            Provider = "okta"
	GoogleWorkspace Provider = "google_workspace"
	MCP             Provider = "mcp"
)

// Providers lists every provider, in code order. Expansion providers
// are appended, never reordered, so the store file-format codes stay stable.
var Providers = []Provider{AWS, Azure, GCP, GitHub, GitLab, Kubernetes, Okta, GoogleWorkspace, MCP}

// Valid reports whether p is a known provider.
func (p Provider) Valid() bool { return in(p, Providers) }

// NodeType is a node type of the attack graph (the canonical model).
type NodeType string

const (
	NodeAccount        NodeType = "account"
	NodeSubscription   NodeType = "subscription"
	NodeProject        NodeType = "project"
	NodeOrganization   NodeType = "organization"
	NodeTenant         NodeType = "tenant"
	NodeIdentity       NodeType = "identity"
	NodeGroup          NodeType = "group"
	NodeRole           NodeType = "role"
	NodePolicy         NodeType = "policy"
	NodeCredential     NodeType = "credential"
	NodeToken          NodeType = "token"
	NodeWorkload       NodeType = "workload"
	NodeCompute        NodeType = "compute"
	NodeNetwork        NodeType = "network"
	NodeEndpoint       NodeType = "endpoint"
	NodeGateway        NodeType = "gateway"
	NodeAPI            NodeType = "api"
	NodeDataStore      NodeType = "data_store"
	NodeSecretStore    NodeType = "secret_store"
	NodeRepository     NodeType = "repository"
	NodePipeline       NodeType = "pipeline"
	NodeArtifact       NodeType = "artifact"
	NodeCluster        NodeType = "cluster"
	NodeNamespace      NodeType = "namespace"
	NodeService        NodeType = "service"
	NodeAIModel        NodeType = "ai_model"
	NodeAIAgent        NodeType = "ai_agent"
	NodeMCPServer      NodeType = "mcp_server"
	NodeTool           NodeType = "tool"
	NodeEndpointDevice NodeType = "endpoint_device"
	NodeVulnerability  NodeType = "vulnerability"
	NodeControl        NodeType = "control"
	NodeBusinessAsset  NodeType = "business_asset"
)

// NodeTypes lists every node type, in code order.
var NodeTypes = []NodeType{
	NodeAccount, NodeSubscription, NodeProject, NodeOrganization, NodeTenant,
	NodeIdentity, NodeGroup, NodeRole, NodePolicy, NodeCredential, NodeToken,
	NodeWorkload, NodeCompute, NodeNetwork, NodeEndpoint, NodeGateway, NodeAPI,
	NodeDataStore, NodeSecretStore, NodeRepository, NodePipeline, NodeArtifact,
	NodeCluster, NodeNamespace, NodeService, NodeAIModel, NodeAIAgent,
	NodeMCPServer, NodeTool, NodeEndpointDevice, NodeVulnerability, NodeControl,
	NodeBusinessAsset,
}

// Valid reports whether t is a known node type.
func (t NodeType) Valid() bool { return in(t, NodeTypes) }

// EdgeKind is an edge type of the attack graph (the canonical model).
type EdgeKind string

const (
	EdgeMemberOf            EdgeKind = "member_of"
	EdgeAssumes             EdgeKind = "assumes"
	EdgeCanImpersonate      EdgeKind = "can_impersonate"
	EdgeCanCreateCredential EdgeKind = "can_create_credential"
	EdgeCanModifyPolicy     EdgeKind = "can_modify_policy"
	EdgeCanExecuteOn        EdgeKind = "can_execute_on"
	EdgeCanRead             EdgeKind = "can_read"
	EdgeCanWrite            EdgeKind = "can_write"
	EdgeCanDelete           EdgeKind = "can_delete"
	EdgeCanExfiltrate       EdgeKind = "can_exfiltrate"
	EdgeExposedTo           EdgeKind = "exposed_to"
	EdgeRoutesTo            EdgeKind = "routes_to"
	EdgeResolvesTo          EdgeKind = "resolves_to"
	EdgeTrusts              EdgeKind = "trusts"
	EdgeFederatesWith       EdgeKind = "federates_with"
	EdgeDeploys             EdgeKind = "deploys"
	EdgeBuilds              EdgeKind = "builds"
	EdgeContainsSecret      EdgeKind = "contains_secret"
	EdgeAccessesData        EdgeKind = "accesses_data"
	EdgeInvokesTool         EdgeKind = "invokes_tool"
	EdgeControlsAgent       EdgeKind = "controls_agent"
	EdgeBypassesControl     EdgeKind = "bypasses_control"
	EdgeMonitoredBy         EdgeKind = "monitored_by"
	EdgeProtectedBy         EdgeKind = "protected_by"
	// EdgeContains is a containment relationship (a repository contains a pipeline, a
	// cluster contains a namespace): the container's compromise reaches what it
	// contains. Added for the expansion domains (ADR-0031); appended so the
	// store codes stay stable.
	EdgeContains EdgeKind = "contains"
)

// EdgeKinds lists every edge kind, in code order.
var EdgeKinds = []EdgeKind{
	EdgeMemberOf, EdgeAssumes, EdgeCanImpersonate, EdgeCanCreateCredential,
	EdgeCanModifyPolicy, EdgeCanExecuteOn, EdgeCanRead, EdgeCanWrite,
	EdgeCanDelete, EdgeCanExfiltrate, EdgeExposedTo, EdgeRoutesTo,
	EdgeResolvesTo, EdgeTrusts, EdgeFederatesWith, EdgeDeploys, EdgeBuilds,
	EdgeContainsSecret, EdgeAccessesData, EdgeInvokesTool, EdgeControlsAgent,
	EdgeBypassesControl, EdgeMonitoredBy, EdgeProtectedBy, EdgeContains,
}

// Valid reports whether k is a known edge kind.
func (k EdgeKind) Valid() bool { return in(k, EdgeKinds) }

// Outcome is a rule outcome. Unknown and Error are never converted to Pass (a
// safety invariant).
type Outcome string

const (
	Pass           Outcome = "pass"
	Fail           Outcome = "fail"
	OutcomeUnknown Outcome = "unknown"
	OutcomeError   Outcome = "error"
	NotApplicable  Outcome = "not_applicable"
)

// Outcomes lists every rule outcome, in code order.
var Outcomes = []Outcome{Pass, Fail, OutcomeUnknown, OutcomeError, NotApplicable}

// Valid reports whether o is a known outcome.
func (o Outcome) Valid() bool { return in(o, Outcomes) }

// ScanStatus is the lifecycle of a scan. An interrupted scan is Incomplete,
// never Completed (threat T-19).
type ScanStatus string

const (
	ScanRunning    ScanStatus = "running"
	ScanCompleted  ScanStatus = "completed"
	ScanFailed     ScanStatus = "failed"
	ScanIncomplete ScanStatus = "incomplete"
)

// ScanStatuses lists every scan status, in code order.
var ScanStatuses = []ScanStatus{ScanRunning, ScanCompleted, ScanFailed, ScanIncomplete}

// Valid reports whether s is a known scan status.
func (s ScanStatus) Valid() bool { return in(s, ScanStatuses) }

// Change is a history change record kind (ADR-0011 §1).
type Change string

const (
	Appeared    Change = "appeared"
	Changed     Change = "changed"
	Disappeared Change = "disappeared"
)

// Changes lists every change kind, in code order.
var Changes = []Change{Appeared, Changed, Disappeared}

// Valid reports whether c is a known change kind.
func (c Change) Valid() bool { return in(c, Changes) }

// Freshness is how current a piece of evidence is.
type Freshness string

const (
	Fresh            Freshness = "fresh"
	Stale            Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

// Freshnesses lists every freshness value, in code order.
var Freshnesses = []Freshness{Fresh, Stale, FreshnessUnknown}

// Valid reports whether f is a known freshness value.
func (f Freshness) Valid() bool { return in(f, Freshnesses) }

// Completeness is whether a collection was exhaustive.
type Completeness string

const (
	Complete            Completeness = "complete"
	Partial             Completeness = "partial"
	CompletenessUnknown Completeness = "unknown"
)

// Completenesses lists every completeness value, in code order.
var Completenesses = []Completeness{Complete, Partial, CompletenessUnknown}

// Valid reports whether c is a known completeness value.
func (c Completeness) Valid() bool { return in(c, Completenesses) }

// TriState answers a yes/no question that may be unknown; unknown is never
// silently read as no (the design's "never convert unknown to pass").
type TriState string

const (
	No      TriState = "no"
	Yes     TriState = "yes"
	Unknown TriState = "unknown"
)

// TriStates lists every tri-state value.
var TriStates = []TriState{No, Yes, Unknown}

// Valid reports whether t is a known tri-state value.
func (t TriState) Valid() bool { return in(t, TriStates) }

// Effect is a permission effect. The effective-permission engine (ADR-0022
// Layer A / Step 4) is the code that writes permissions, so the vocabulary is
// fixed here now (closing the permissions.effect part of blocker B-5). A deny
// always overrides an allow (ADR-0022 §5); unknown is never converted to allow.
type Effect string

const (
	// EffectAllow is a granted effective permission.
	EffectAllow Effect = "allow"
	// EffectDeny is an effective permission removed by an explicit deny, a
	// deny-assignment, a deny policy, or a permission-boundary cap. A deny
	// overrides an allow.
	EffectDeny Effect = "deny"
)

// Effects lists every effect, in code order. The vocabulary only grows at the
// end and a name is never reused (matching the other enumerations).
var Effects = []Effect{EffectAllow, EffectDeny}

// Valid reports whether e is a known effect.
func (e Effect) Valid() bool { return in(e, Effects) }

// Zone is an exposure's source zone. The internet reachability engine (ADR-0024)
// is the code that writes exposures, so the vocabulary is fixed here now (closing
// the exposures.source_zone part of blocker B-5).
type Zone string

const (
	// ZoneInternet is the public internet: a source that admits 0.0.0.0/0, ::/0,
	// the Internet service tag, or "*".
	ZoneInternet Zone = "internet"
	// ZoneVPC is within the resource's own private network.
	ZoneVPC Zone = "vpc"
	// ZoneUnknown is a source the collected data could not classify (for example an
	// unresolved service tag); never silently treated as internet or as private.
	ZoneUnknown Zone = "unknown"
)

// Zones lists every zone, in code order. The vocabulary only grows at the end and
// a name is never reused.
var Zones = []Zone{ZoneInternet, ZoneVPC, ZoneUnknown}

// Valid reports whether z is a known zone.
func (z Zone) Valid() bool { return in(z, Zones) }

// Sensitivity is an asset's data-sensitivity classification. The classification
// engine (ADR-0025) is the code that writes it, from collected metadata alone
// (tags, resource nature, naming signals), with a confidence and a transparent
// method. It is an ordered vocabulary; SensitivityUnknown is the fail-closed state
// and is never treated as SensitivityLow (an unclassifiable asset is never read as
// non-sensitive). It closes the classification.label part of blocker B-5.
type Sensitivity string

const (
	// SensitivityHigh: strong signals that the asset holds or controls sensitive
	// data (a declared classification tag, or a key/secret store, or a data store
	// with a sensitive naming signal).
	SensitivityHigh Sensitivity = "high"
	// SensitivityModerate: the asset is data-bearing or has a suggestive signal,
	// but its sensitivity is not established at high confidence.
	SensitivityModerate Sensitivity = "moderate"
	// SensitivityLow: a positive signal that the asset is non-sensitive (a declared
	// public/internal classification, or an inherently public resource). Never the
	// default for an asset that could not be classified.
	SensitivityLow Sensitivity = "low"
	// SensitivityUnknown: the collected metadata was insufficient to classify the
	// asset. The fail-closed state, distinct from low; downstream treats it as
	// possibly sensitive, never as not sensitive.
	SensitivityUnknown Sensitivity = "unknown"
)

// Sensitivities lists every sensitivity, most sensitive first. The vocabulary only
// grows and a name is never reused.
var Sensitivities = []Sensitivity{SensitivityHigh, SensitivityModerate, SensitivityLow, SensitivityUnknown}

// Valid reports whether s is a known sensitivity.
func (s Sensitivity) Valid() bool { return in(s, Sensitivities) }

// Severity is a detection's base severity: how bad the class of issue is, a
// property of the detection known when the rule is authored (ADR-0027). It is
// distinct from confidence (how sure we are the finding is real) and from business
// impact (how much the affected asset matters). The risk model (internal/risk) maps
// it to a documented sub-score.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Severities lists every severity, most severe first.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return in(s, Severities) }

// FindingStatus is the lifecycle of a finding (open, resolved, and so on). Its
// vocabulary is deferred until the detection engine writes findings (blocker
// B-5); no values are fixed here yet.
type FindingStatus string
