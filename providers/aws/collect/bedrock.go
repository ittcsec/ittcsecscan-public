package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// bedrockCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const bedrockCollectorID = "collector:aws.bedrock.agents"

// bedrockAPIVersion is the Agents for Amazon Bedrock control-plane API version,
// recorded as evidence provenance (the service's API date).
const bedrockAPIVersion = "2023-06-05"

// agentVersionDraft is the working (authoritative current configuration) version
// of an agent. The collector reads the DRAFT configuration, which is the agent's
// current intent; numbered version snapshots behind aliases are not enumerated in
// this slice (a documented scope choice, docs/known-limitations.md), so the config
// a scan reports is the one an operator is currently editing, never a stale alias.
const agentVersionDraft = "DRAFT"

// The completeness service names this collector records, per region: the agent
// listing, and the per-agent action-group and knowledge-base detail passes
// (list-plus-detail, following the KMS/S3 shape).
const (
	svcBedrockAgents         = "bedrock.agents"
	svcBedrockActionGroups   = "bedrock.actionGroups"
	svcBedrockKnowledgeBases = "bedrock.knowledgeBases"
)

// bedrockAPI is the read-only Agents for Amazon Bedrock control-plane surface the
// collector uses (AWS "Agents for Amazon Bedrock" API reference, verified
// 2026-10-02). Every call is a List or Get of configuration; none invokes an
// agent, runs a model, or returns a prompt, data value, or secret. Each call takes
// optFns so the collector targets one declared region.
type bedrockAPI interface {
	ListAgents(context.Context, *bedrockagent.ListAgentsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error)
	GetAgent(context.Context, *bedrockagent.GetAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error)
	ListAgentActionGroups(context.Context, *bedrockagent.ListAgentActionGroupsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentActionGroupsOutput, error)
	GetAgentActionGroup(context.Context, *bedrockagent.GetAgentActionGroupInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentActionGroupOutput, error)
	ListAgentKnowledgeBases(context.Context, *bedrockagent.ListAgentKnowledgeBasesInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentKnowledgeBasesOutput, error)
	ListDataSources(context.Context, *bedrockagent.ListDataSourcesInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListDataSourcesOutput, error)
	GetDataSource(context.Context, *bedrockagent.GetDataSourceInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetDataSourceOutput, error)
}

// BedrockAgentsCollector reads the account's Agents for Amazon Bedrock in each
// declared region (ADR-0019 section 1): each agent, the action-group tools it is
// configured to invoke, and the knowledge-base data sources it is connected to. It
// is the evidence-grounded producer for the reserved invokes_tool and accesses_data
// edges (ADR-0033): both come from the agent's own collected configuration, by
// native id, never from a name or tag.
//
// It emits only non-secret structural fields. An action group's executor is recorded
// as the Lambda ARN (a reference for the join), never resolved; a knowledge base's
// data source is recorded by its backing resource id (for an S3 source, the bucket
// ARN, which joins the S3 collector's bucket node). The agent's instruction text,
// prompts, and any encryption-key or data values are never emitted.
type BedrockAgentsCollector struct {
	account string
	api     bedrockAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewBedrockAgentsCollector builds the collector with a read-only Bedrock Agents
// client from the adapter's resolved config (ADR-0018 section 3), over the declared
// region set.
func NewBedrockAgentsCollector(account string, cfg awssdk.Config, budget *collect.Budget) *BedrockAgentsCollector {
	return &BedrockAgentsCollector{account: account, api: bedrockagent.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newBedrockAgentsCollector is the injectable constructor tests use with a stub API
// and an explicit region list. It has no budget (unlimited).
func newBedrockAgentsCollector(account string, api bedrockAPI, regions []string) *BedrockAgentsCollector {
	return &BedrockAgentsCollector{account: account, api: api, regions: regions}
}

func (c *BedrockAgentsCollector) ID() string               { return bedrockCollectorID }
func (c *BedrockAgentsCollector) Provider() model.Provider { return model.AWS }

// bedrockRequirements are the read-only permissions this collector needs. Each maps
// to a bedrock: action of the same name (AWS "Actions, resources, and condition keys
// for Amazon Bedrock", verified 2026-10-02). Registered at init so the templates
// reconcile against real code (ADR-0016). These are compared against the provider's
// own documentation and a live access-denied test before the permission set is
// accepted (ADR-0033 build plan).
func bedrockRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: bedrockCollectorID}
	}
	return []permissions.Requirement{
		req("bedrock:ListAgents"),
		req("bedrock:GetAgent"),
		req("bedrock:ListAgentActionGroups"),
		req("bedrock:GetAgentActionGroup"),
		req("bedrock:ListAgentKnowledgeBases"),
		req("bedrock:ListDataSources"),
		req("bedrock:GetDataSource"),
	}
}

func init() {
	for _, r := range bedrockRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *BedrockAgentsCollector) Requirements() []permissions.Requirement {
	return bedrockRequirements()
}

// bedrockServices lists every completeness service, in order, for marking the
// resources not reached once the shared budget is exhausted.
func bedrockServices() []string {
	return []string{svcBedrockAgents, svcBedrockActionGroups, svcBedrockKnowledgeBases}
}

// Collect enumerates agents in every declared region, sequentially (ADR-0019
// section 1), recording one completeness record per (service, region). A denied,
// throttled, not-enabled, or unreachable read is a represented gap and the other
// regions still run; budget exhaustion marks every (service, region) not yet reached
// Partial "budget exhausted". A region where the service is not offered surfaces as
// an honest Unsupported or unreachable gap, never a silent skip and never a false
// empty.
func (c *BedrockAgentsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			for _, s := range bedrockServices() {
				_ = sink.Complete(c.budgetGap(s, region))
			}
			continue
		}
		budgetOut, err := c.collectRegion(ctx, sink, region)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, err)
		}
		exhausted = budgetOut
	}
	return errors.Join(errs...)
}

// agentRef is an agent to detail: its id and ARN.
type agentRef struct{ id, arn string }

// collectRegion lists the agents in one region, then details each agent's
// configuration (the node and its action-group and knowledge-base edges).
func (c *BedrockAgentsCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var errs []error

	agents, listed, bo, err := c.collectAgents(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcBedrockActionGroups, svcBedrockKnowledgeBases)
		return true, errors.Join(errs...)
	}
	if !listed {
		// The agent listing for this region did not complete (the service is not offered
		// here, the region is unreachable, or the read was denied). collectAgents already
		// propagated that same gap to the action-group and knowledge-base services, so
		// there is nothing to assess in this region; do not report those services complete.
		return false, errors.Join(errs...)
	}

	agDone, kbDone := 0, 0
	agReason, kbReason := "", ""
	for _, a := range agents {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcBedrockActionGroups, region, agDone))
			_ = sink.Complete(c.cancelledGap(svcBedrockKnowledgeBases, region, kbDone))
			return false, err
		}
		bo, reason := c.collectActionGroups(ctx, sink, region, a)
		if bo {
			_ = sink.Complete(c.budgetGap(svcBedrockActionGroups, region))
			_ = sink.Complete(c.budgetGap(svcBedrockKnowledgeBases, region))
			return true, errors.Join(errs...)
		}
		if reason != "" {
			agReason = reason
		} else {
			agDone++
		}

		bo, reason = c.collectKnowledgeBases(ctx, sink, region, a)
		if bo {
			_ = sink.Complete(c.completeReason(svcBedrockActionGroups, region, agDone, agReason))
			_ = sink.Complete(c.budgetGap(svcBedrockKnowledgeBases, region))
			return true, errors.Join(errs...)
		}
		if reason != "" {
			kbReason = reason
		} else {
			kbDone++
		}
	}
	_ = sink.Complete(c.completeReason(svcBedrockActionGroups, region, agDone, agReason))
	_ = sink.Complete(c.completeReason(svcBedrockKnowledgeBases, region, kbDone, kbReason))
	return false, errors.Join(errs...)
}

// collectAgents paginates ListAgents, then details each agent (GetAgent for the ARN,
// execution role, model, and guardrail), emits the ai_agent node and its assumes
// edge to the execution role, and records svcBedrockAgents.
//
// It returns the agents to detail, whether the agent listing itself completed (listed),
// whether the budget was exhausted (budgetOut), and any error to surface. When the listing
// does not complete, it also propagates that same gap to the action-group and knowledge-base
// services for the region, since neither can be assessed without the agent list.
func (c *BedrockAgentsCollector) collectAgents(ctx context.Context, sink collect.Sink, region string) (agents []agentRef, listed, budgetOut bool, err error) {
	var summaries []bedrocktypes.AgentSummary
	in := &bedrockagent.ListAgentsInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcBedrockAgents, region, len(summaries)))
			return nil, false, false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcBedrockAgents, region))
			return nil, false, true, nil
		}
		out, err := c.api.ListAgents(ctx, in, bedrockInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcBedrockAgents, region, len(summaries)))
				return nil, false, false, cerr
			}
			// The agent listing failed. Record its classified gap, and mirror the same gap
			// onto the per-agent services so an unsupported or unreachable region is never
			// reported as having complete action-group / knowledge-base coverage.
			comp := c.completeness(svcBedrockAgents, region, len(summaries), err)
			_ = sink.Complete(comp)
			_ = sink.Complete(c.mirrorGap(svcBedrockActionGroups, region, comp))
			_ = sink.Complete(c.mirrorGap(svcBedrockKnowledgeBases, region, comp))
			if comp.Status == collect.Errored {
				return nil, false, false, err
			}
			return nil, false, false, nil
		}
		_ = sink.Evidence(c.evidence("ListAgents", region, out))
		summaries = append(summaries, out.AgentSummaries...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
	}

	agents = make([]agentRef, 0, len(summaries))
	agentGap := ""
	for _, s := range summaries {
		ref, gap := c.detailAgent(ctx, sink, region, deref(s.AgentId))
		if gap == budgetExhausted {
			_ = sink.Complete(c.budgetGap(svcBedrockAgents, region))
			return agents, true, true, nil
		}
		if gap != "" {
			// A per-agent GetAgent failure leaves the agent unkeyable; it is a recorded
			// coverage gap, never a silently smaller agent count read as "nothing there".
			agentGap = gap
		}
		if ref.arn != "" {
			agents = append(agents, ref)
		}
	}
	_ = sink.Complete(c.completeReason(svcBedrockAgents, region, len(agents), agentGap))
	return agents, true, false, nil
}

// detailAgent reads one agent's configuration and emits the ai_agent node (keyed by
// agent ARN) and the assumes edge to its execution role. A gather gap does not drop
// the agent if the ARN is known; a missing ARN (the id could not be resolved) yields
// no node, since the graph is keyed by native id.
func (c *BedrockAgentsCollector) detailAgent(ctx context.Context, sink collect.Sink, region, agentID string) (agentRef, string) {
	if agentID == "" {
		return agentRef{}, ""
	}
	if !c.budget.Spend() {
		return agentRef{}, budgetExhausted
	}
	out, err := c.api.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: &agentID}, bedrockInRegion(region))
	if err != nil {
		// Without GetAgent the ARN is unknown, so the agent cannot be keyed; it is a
		// per-agent gap recorded by the caller's completeness, not a dropped-to-pass.
		return agentRef{id: agentID}, c.callGap(err)
	}
	_ = sink.Evidence(c.evidence("GetAgent", region, out))
	ag := out.Agent
	if ag == nil || deref(ag.AgentArn) == "" {
		return agentRef{id: agentID}, ""
	}
	arn := deref(ag.AgentArn)
	roleARN := deref(ag.AgentResourceRoleArn)
	a := attrs(
		"region", region,
		"source", "bedrock-agents",
		"foundation_model", deref(ag.FoundationModel),
		"agent_status", string(ag.AgentStatus),
		"has_guardrail", boolStr(ag.GuardrailConfiguration != nil && deref(ag.GuardrailConfiguration.GuardrailIdentifier) != ""),
		"execution_role", roleARN,
	)
	_ = sink.Node(collect.Node{Type: model.NodeAIAgent, NativeID: arn, Name: deref(ag.AgentName), Attributes: a})
	if roleARN != "" {
		// The execution role the Bedrock runtime assumes to act for this agent. It
		// joins the IAM collector's role node, so the effective-privilege engine
		// (ADR-0022) resolves the agent's agency over the collected authorization graph.
		_ = sink.Link(collect.Link{SourceNativeID: arn, TargetNativeID: roleARN, Kind: model.EdgeAssumes})
	}
	return agentRef{id: agentID, arn: arn}, ""
}

// collectActionGroups paginates the agent's action groups, details each, and emits a
// tool node and an invokes_tool edge per group. It returns (budgetOut, gapReason).
func (c *BedrockAgentsCollector) collectActionGroups(ctx context.Context, sink collect.Sink, region string, a agentRef) (bool, string) {
	var summaries []bedrocktypes.ActionGroupSummary
	in := &bedrockagent.ListAgentActionGroupsInput{AgentId: &a.id, AgentVersion: awssdk.String(agentVersionDraft)}
	for {
		if err := ctx.Err(); err != nil {
			return false, "cancelled"
		}
		if !c.budget.Spend() {
			return true, ""
		}
		out, err := c.api.ListAgentActionGroups(ctx, in, bedrockInRegion(region))
		if err != nil {
			return false, c.callGap(err)
		}
		_ = sink.Evidence(c.evidence("ListAgentActionGroups", region, out))
		summaries = append(summaries, out.ActionGroupSummaries...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
	}

	gap := ""
	for _, s := range summaries {
		if !c.budget.Spend() {
			return true, gap
		}
		det, err := c.api.GetAgentActionGroup(ctx, &bedrockagent.GetAgentActionGroupInput{
			AgentId: &a.id, AgentVersion: awssdk.String(agentVersionDraft), ActionGroupId: s.ActionGroupId,
		}, bedrockInRegion(region))
		if err != nil {
			gap = c.callGap(err)
			continue
		}
		_ = sink.Evidence(c.evidence("GetAgentActionGroup", region, det))
		c.emitActionGroup(sink, region, a, det.AgentActionGroup)
	}
	return false, gap
}

// emitActionGroup emits one tool node (keyed by a stable agent-scoped id) and the
// invokes_tool edge from the agent to it. The tool's facts are the structurally
// verifiable properties of the action group: whether it is enabled, its executor
// kind, whether it is a code-execution capability, and whether its Lambda executor
// is in another account (a tool-execution trust-boundary crossing visible from the
// ARN). These are what the AIG-TOOL detection reads; none is a name heuristic.
func (c *BedrockAgentsCollector) emitActionGroup(sink collect.Sink, region string, a agentRef, ag *bedrocktypes.AgentActionGroup) {
	if ag == nil {
		return
	}
	groupID := deref(ag.ActionGroupId)
	if groupID == "" {
		return
	}
	toolID := a.arn + "/action-group/" + groupID
	signature := string(ag.ParentActionSignature)
	kind, lambda := executorFacts(ag.ActionGroupExecutor)
	state := strings.ToLower(string(ag.ActionGroupState))
	attr := attrs(
		"region", region,
		"source", "bedrock-action-group",
		"agent", a.arn,
		"state", state,
		"executor_kind", kind,
		"executor_lambda", lambda,
		"signature", signature,
		"code_execution", boolStr(signature == signatureCodeInterpreter),
		"cross_account", boolStr(isCrossAccountLambda(c.account, lambda)),
	)
	_ = sink.Node(collect.Node{Type: model.NodeTool, NativeID: toolID, Name: deref(ag.ActionGroupName), Attributes: attr})
	_ = sink.Link(collect.Link{SourceNativeID: a.arn, TargetNativeID: toolID, Kind: model.EdgeInvokesTool, Conditions: condition("state", state)})
}

// collectKnowledgeBases paginates the agent's knowledge bases, and for each reads its
// data sources, emitting a data_store node and an accesses_data edge per source. It
// returns (budgetOut, gapReason).
func (c *BedrockAgentsCollector) collectKnowledgeBases(ctx context.Context, sink collect.Sink, region string, a agentRef) (bool, string) {
	var summaries []bedrocktypes.AgentKnowledgeBaseSummary
	in := &bedrockagent.ListAgentKnowledgeBasesInput{AgentId: &a.id, AgentVersion: awssdk.String(agentVersionDraft)}
	for {
		if err := ctx.Err(); err != nil {
			return false, "cancelled"
		}
		if !c.budget.Spend() {
			return true, ""
		}
		out, err := c.api.ListAgentKnowledgeBases(ctx, in, bedrockInRegion(region))
		if err != nil {
			return false, c.callGap(err)
		}
		_ = sink.Evidence(c.evidence("ListAgentKnowledgeBases", region, out))
		summaries = append(summaries, out.AgentKnowledgeBaseSummaries...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
	}

	gap := ""
	for _, s := range summaries {
		bo, reason := c.collectDataSources(ctx, sink, region, a, deref(s.KnowledgeBaseId))
		if bo {
			return true, gap
		}
		if reason != "" {
			gap = reason
		}
	}
	return false, gap
}

// collectDataSources enumerates one knowledge base's data sources and emits, for each,
// a data_store node and the accesses_data edge from the agent to it. An S3 source is
// keyed by its bucket ARN so it joins the S3 collector's bucket node (and that node's
// sensitivity and exposure facts); a non-S3 (for example WEB) source is keyed by a
// synthetic id and marked external.
func (c *BedrockAgentsCollector) collectDataSources(ctx context.Context, sink collect.Sink, region string, a agentRef, kbID string) (bool, string) {
	if kbID == "" {
		return false, ""
	}
	var summaries []bedrocktypes.DataSourceSummary
	in := &bedrockagent.ListDataSourcesInput{KnowledgeBaseId: &kbID}
	for {
		if err := ctx.Err(); err != nil {
			return false, "cancelled"
		}
		if !c.budget.Spend() {
			return true, ""
		}
		out, err := c.api.ListDataSources(ctx, in, bedrockInRegion(region))
		if err != nil {
			return false, c.callGap(err)
		}
		_ = sink.Evidence(c.evidence("ListDataSources", region, out))
		summaries = append(summaries, out.DataSourceSummaries...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
	}

	gap := ""
	for _, s := range summaries {
		if !c.budget.Spend() {
			return true, gap
		}
		det, err := c.api.GetDataSource(ctx, &bedrockagent.GetDataSourceInput{KnowledgeBaseId: &kbID, DataSourceId: s.DataSourceId}, bedrockInRegion(region))
		if err != nil {
			gap = c.callGap(err)
			continue
		}
		_ = sink.Evidence(c.evidence("GetDataSource", region, det))
		c.emitDataSource(sink, region, a, kbID, det.DataSource)
	}
	return false, gap
}

// emitDataSource emits one data_store node for a knowledge-base data source and the
// accesses_data edge from the agent to it. For an S3 source the node is keyed by the
// bucket ARN (joining the S3 collector); for any other source it is keyed by a
// synthetic id and marked external, which is the AIG-TOOL/AIG-DATA signal that the
// agent is grounded on data outside the collected account surface.
func (c *BedrockAgentsCollector) emitDataSource(sink collect.Sink, region string, a agentRef, kbID string, ds *bedrocktypes.DataSource) {
	if ds == nil {
		return
	}
	dsType, bucketARN := dataSourceFacts(ds.DataSourceConfiguration)
	var target string
	var node collect.Node
	if bucketARN != "" {
		target = bucketARN
		// Minimal, additive attributes only: the S3 collector owns this bucket node
		// and its sensitivity/policy facts (merge is first-seen-wins, later-fills-gaps,
		// ADR-0014), so the connection is recorded without clobbering the richer node.
		node = collect.Node{Type: model.NodeDataStore, NativeID: target, Attributes: attrs(
			"accessed_by_agent", a.arn, "kb_id", kbID, "ds_type", dsType,
		)}
	} else {
		dsID := deref(ds.DataSourceId)
		target = "bedrock:datasource:" + kbID + ":" + dsID
		node = collect.Node{Type: model.NodeDataStore, NativeID: target, Name: deref(ds.Name), Attributes: attrs(
			"region", region, "source", "bedrock-kb", "kb_id", kbID, "ds_type", dsType, "external", "true",
		)}
	}
	_ = sink.Node(node)
	_ = sink.Link(collect.Link{SourceNativeID: a.arn, TargetNativeID: target, Kind: model.EdgeAccessesData, Conditions: condition("ds_type", dsType)})
}

// bedrockInRegion targets one Bedrock Agents call at a declared region.
func bedrockInRegion(region string) func(*bedrockagent.Options) {
	return func(o *bedrockagent.Options) { o.Region = region }
}

// budgetExhausted is the sentinel gap reason that stops a detail pass.
const budgetExhausted = "budget exhausted"

// signatureCodeInterpreter is the built-in action-group signature that grants an
// agent sandboxed code execution (AWS Bedrock agent built-in action-group
// signatures, verified 2026-10-02): the maximal tool-privilege capability.
const signatureCodeInterpreter = "AMAZON.CodeInterpreter"

// executorFacts returns the executor kind and, when the executor is a Lambda, its
// ARN. The union has a Lambda member (a function the agent invokes) and a custom-
// control member (RETURN_CONTROL: tool execution handed back to the calling
// application). An unset executor yields an empty kind.
func executorFacts(e bedrocktypes.ActionGroupExecutor) (kind, lambda string) {
	switch v := e.(type) {
	case *bedrocktypes.ActionGroupExecutorMemberLambda:
		return "lambda", v.Value
	case *bedrocktypes.ActionGroupExecutorMemberCustomControl:
		return "custom_control", ""
	default:
		return "", ""
	}
}

// isCrossAccountLambda reports whether a Lambda executor ARN belongs to a different
// account than the scanned one: the agent invokes code in another account, a tool-
// execution trust-boundary crossing. An unparseable or same-account ARN is not
// cross-account (false), never an assumed yes.
func isCrossAccountLambda(account, lambdaARN string) bool {
	if lambdaARN == "" || account == "" {
		return false
	}
	// arn:partition:service:region:account-id:resource
	parts := strings.SplitN(lambdaARN, ":", 6)
	if len(parts) < 6 {
		return false
	}
	return parts[4] != "" && parts[4] != account
}

// dataSourceFacts returns a data source's type and, when it is an S3 source, the
// backing bucket ARN. The configuration union carries one typed member; only the S3
// member exposes a resource id that joins a collected node.
func dataSourceFacts(cfg *bedrocktypes.DataSourceConfiguration) (dsType, bucketARN string) {
	if cfg == nil {
		return "", ""
	}
	dsType = string(cfg.Type)
	if cfg.S3Configuration != nil {
		bucketARN = deref(cfg.S3Configuration.BucketArn)
	}
	return dsType, bucketARN
}

// condition returns a single-pair condition map, or nil for an empty value, so an
// edge records a qualifier only when there is one.
func condition(k, v string) map[string]string {
	if v == "" {
		return nil
	}
	return map[string]string{k: v}
}

// boolStr renders a bool as the canonical "true"/"false" fact value.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// callGap classifies a per-agent/per-resource read error into a gap reason (never
// empty), so a failed detail read is an honest gap, never a silent empty.
func (c *BedrockAgentsCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isRegionNotEnabled(err):
		return "region not enabled"
	case isTransport(err):
		return "unreachable"
	}
	return redact.String(err.Error())
}

// mirrorGap reproduces another service's completeness status and reason for a region, so a
// per-agent service inherits the agent listing's gap when the listing itself did not
// complete (collected is zero: nothing could be assessed).
func (c *BedrockAgentsCollector) mirrorGap(service, region string, comp collect.Completeness) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: comp.Status, Reason: comp.Reason}
}

// completeness classifies a Bedrock list error into a completeness record. A not-
// enabled or service-absent region is Unsupported, a denial Denied, a throttle or a
// transport failure Partial, anything else Errored.
func (c *BedrockAgentsCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status = collect.Unsupported
		reason = "region not enabled"
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isTransport(err):
		status = collect.Partial
		reason = "unreachable"
	}
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

// completeReason records a detail pass as Complete, or Partial when a per-resource
// gap was seen, so an agent whose action groups or knowledge bases could not be fully
// read is never reported as fully assessed.
func (c *BedrockAgentsCollector) completeReason(service, region string, collected int, reason string) collect.Completeness {
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

func (c *BedrockAgentsCollector) budgetGap(service, region string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: budgetExhausted}
}

func (c *BedrockAgentsCollector) cancelledGap(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: collected, Reason: "cancelled"}
}

func (c *BedrockAgentsCollector) markBudget(sink collect.Sink, region string, services ...string) {
	for _, s := range services {
		_ = sink.Complete(c.budgetGap(s, region))
	}
}

func (c *BedrockAgentsCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one Bedrock read. The agent
// configuration carries an instruction (prompt) field and may reference an encryption
// key; redaction is applied as defence in depth over the already structural response.
func (c *BedrockAgentsCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "bedrock", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: bedrockAPIVersion, Collector: bedrockCollectorID},
	}
}
