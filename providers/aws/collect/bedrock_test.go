package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubBedrock is an offline bedrockAPI: a fixed estate served in every region,
// recording each call's region, with per-"op@region" error injection.
type stubBedrock struct {
	agents            []bedrocktypes.AgentSummary
	agentDetail       map[string]*bedrocktypes.Agent                      // by agent id
	actionGroups      map[string][]bedrocktypes.ActionGroupSummary        // by agent id
	actionGroupDetail map[string]*bedrocktypes.AgentActionGroup           // by action-group id
	kbs               map[string][]bedrocktypes.AgentKnowledgeBaseSummary // by agent id
	dataSources       map[string][]bedrocktypes.DataSourceSummary         // by kb id
	dataSourceDetail  map[string]*bedrocktypes.DataSource                 // by data-source id

	errs    map[string]error
	calls   int
	regions []string
}

func bedrockRegion(opts []func(*bedrockagent.Options)) string {
	var o bedrockagent.Options
	for _, f := range opts {
		f(&o)
	}
	return o.Region
}

func (s *stubBedrock) hit(op string, o []func(*bedrockagent.Options)) error {
	s.calls++
	r := bedrockRegion(o)
	s.regions = append(s.regions, r)
	return s.errs[op+"@"+r]
}

func (s *stubBedrock) ListAgents(_ context.Context, _ *bedrockagent.ListAgentsInput, o ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error) {
	if err := s.hit("ListAgents", o); err != nil {
		return nil, err
	}
	return &bedrockagent.ListAgentsOutput{AgentSummaries: s.agents}, nil
}

func (s *stubBedrock) GetAgent(_ context.Context, in *bedrockagent.GetAgentInput, o ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	if err := s.hit("GetAgent", o); err != nil {
		return nil, err
	}
	return &bedrockagent.GetAgentOutput{Agent: s.agentDetail[deref(in.AgentId)]}, nil
}

func (s *stubBedrock) ListAgentActionGroups(_ context.Context, in *bedrockagent.ListAgentActionGroupsInput, o ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentActionGroupsOutput, error) {
	if err := s.hit("ListAgentActionGroups", o); err != nil {
		return nil, err
	}
	return &bedrockagent.ListAgentActionGroupsOutput{ActionGroupSummaries: s.actionGroups[deref(in.AgentId)]}, nil
}

func (s *stubBedrock) GetAgentActionGroup(_ context.Context, in *bedrockagent.GetAgentActionGroupInput, o ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentActionGroupOutput, error) {
	if err := s.hit("GetAgentActionGroup", o); err != nil {
		return nil, err
	}
	return &bedrockagent.GetAgentActionGroupOutput{AgentActionGroup: s.actionGroupDetail[deref(in.ActionGroupId)]}, nil
}

func (s *stubBedrock) ListAgentKnowledgeBases(_ context.Context, in *bedrockagent.ListAgentKnowledgeBasesInput, o ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentKnowledgeBasesOutput, error) {
	if err := s.hit("ListAgentKnowledgeBases", o); err != nil {
		return nil, err
	}
	return &bedrockagent.ListAgentKnowledgeBasesOutput{AgentKnowledgeBaseSummaries: s.kbs[deref(in.AgentId)]}, nil
}

func (s *stubBedrock) ListDataSources(_ context.Context, in *bedrockagent.ListDataSourcesInput, o ...func(*bedrockagent.Options)) (*bedrockagent.ListDataSourcesOutput, error) {
	if err := s.hit("ListDataSources", o); err != nil {
		return nil, err
	}
	return &bedrockagent.ListDataSourcesOutput{DataSourceSummaries: s.dataSources[deref(in.KnowledgeBaseId)]}, nil
}

func (s *stubBedrock) GetDataSource(_ context.Context, in *bedrockagent.GetDataSourceInput, o ...func(*bedrockagent.Options)) (*bedrockagent.GetDataSourceOutput, error) {
	if err := s.hit("GetDataSource", o); err != nil {
		return nil, err
	}
	return &bedrockagent.GetDataSourceOutput{DataSource: s.dataSourceDetail[deref(in.DataSourceId)]}, nil
}

const (
	agentID   = "AGENT12345"
	agentARN  = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
	execRole  = "arn:aws:iam::123456789012:role/bedrock-exec"
	lambdaX   = "arn:aws:lambda:us-east-1:999999999999:function:ext-tool" // cross-account
	lambdaOwn = "arn:aws:lambda:us-east-1:123456789012:function:own-tool"
	agLambda  = "ACTIONLMBD"
	agCode    = "ACTIONCODE"
	kbID      = "KB12345678"
	bucketARN = "arn:aws:s3:::rag-corpus"
	webDSID   = "DSWEB0001"
)

// oneAgentStub builds an estate with one agent that has a cross-account Lambda tool,
// a code-interpreter tool, and a knowledge base backed by one S3 source and one
// external (web) source.
func oneAgentStub() *stubBedrock {
	return &stubBedrock{
		agents: []bedrocktypes.AgentSummary{{AgentId: ptr(agentID), AgentName: ptr("support-bot"), AgentStatus: bedrocktypes.AgentStatus("PREPARED")}},
		agentDetail: map[string]*bedrocktypes.Agent{agentID: {
			AgentArn: ptr(agentARN), AgentId: ptr(agentID), AgentName: ptr("support-bot"),
			AgentResourceRoleArn: ptr(execRole), AgentStatus: bedrocktypes.AgentStatus("PREPARED"),
			FoundationModel:        ptr("example-vendor.example-model-1"),
			GuardrailConfiguration: &bedrocktypes.GuardrailConfiguration{GuardrailIdentifier: ptr("gr-1")},
		}},
		actionGroups: map[string][]bedrocktypes.ActionGroupSummary{agentID: {
			{ActionGroupId: ptr(agLambda), ActionGroupName: ptr("db-tools"), ActionGroupState: bedrocktypes.ActionGroupState("ENABLED")},
			{ActionGroupId: ptr(agCode), ActionGroupName: ptr("code"), ActionGroupState: bedrocktypes.ActionGroupState("ENABLED")},
		}},
		actionGroupDetail: map[string]*bedrocktypes.AgentActionGroup{
			agLambda: {
				ActionGroupId: ptr(agLambda), ActionGroupName: ptr("db-tools"),
				ActionGroupState:    bedrocktypes.ActionGroupState("ENABLED"),
				ActionGroupExecutor: &bedrocktypes.ActionGroupExecutorMemberLambda{Value: lambdaX},
			},
			agCode: {
				ActionGroupId: ptr(agCode), ActionGroupName: ptr("code"),
				ActionGroupState:      bedrocktypes.ActionGroupState("ENABLED"),
				ParentActionSignature: bedrocktypes.ActionGroupSignature(signatureCodeInterpreter),
			},
		},
		kbs: map[string][]bedrocktypes.AgentKnowledgeBaseSummary{agentID: {
			{KnowledgeBaseId: ptr(kbID), KnowledgeBaseState: bedrocktypes.KnowledgeBaseState("ENABLED")},
		}},
		dataSources: map[string][]bedrocktypes.DataSourceSummary{kbID: {
			{DataSourceId: ptr("DSS30001"), Name: ptr("corpus")},
			{DataSourceId: ptr(webDSID), Name: ptr("crawler")},
		}},
		dataSourceDetail: map[string]*bedrocktypes.DataSource{
			"DSS30001": {DataSourceId: ptr("DSS30001"), Name: ptr("corpus"), DataSourceConfiguration: &bedrocktypes.DataSourceConfiguration{
				Type: bedrocktypes.DataSourceType("S3"), S3Configuration: &bedrocktypes.S3DataSourceConfiguration{BucketArn: ptr(bucketARN)},
			}},
			webDSID: {DataSourceId: ptr(webDSID), Name: ptr("crawler"), DataSourceConfiguration: &bedrocktypes.DataSourceConfiguration{
				Type: bedrocktypes.DataSourceType("WEB"),
			}},
		},
	}
}

func runBedrock(t *testing.T, regions []string, api bedrockAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newBedrockAgentsCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodeOf(s collect.Scan, typ model.NodeType, id string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == typ && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

func hasLink(s collect.Scan, kind model.EdgeKind, src, dst string) bool {
	for _, l := range s.Links {
		if l.Kind == kind && l.SourceNativeID == src && l.TargetNativeID == dst {
			return true
		}
	}
	return false
}

// TestBedrockMapsAgentToolAndData proves the collector turns an agent's own
// configuration into the ai_agent node, the assumes edge to its execution role, the
// invokes_tool edges to its action-group tools (with the code-execution and
// cross-account facts), and the accesses_data edges to its knowledge-base data stores
// (the S3 source keyed by bucket ARN for the join, the web source marked external).
func TestBedrockMapsAgentToolAndData(t *testing.T) {
	s := runBedrock(t, oneRegion, oneAgentStub())

	ag, ok := nodeOf(s, model.NodeAIAgent, agentARN)
	if !ok {
		t.Fatal("agent not emitted as an ai_agent node keyed by ARN")
	}
	if ag.Name != "support-bot" {
		t.Errorf("agent name = %q", ag.Name)
	}
	for k, v := range map[string]string{
		"source": "bedrock-agents", "foundation_model": "example-vendor.example-model-1",
		"agent_status": "PREPARED", "has_guardrail": "true", "execution_role": execRole, "region": "us-east-1",
	} {
		if ag.Attributes[k] != v {
			t.Errorf("agent attr %s = %q, want %q", k, ag.Attributes[k], v)
		}
	}
	if !hasLink(s, model.EdgeAssumes, agentARN, execRole) {
		t.Error("missing assumes edge agent -> execution role (grounds effective privilege)")
	}

	lambdaTool := agentARN + "/action-group/" + agLambda
	lt, ok := nodeOf(s, model.NodeTool, lambdaTool)
	if !ok {
		t.Fatal("lambda action group not emitted as a tool node")
	}
	for k, v := range map[string]string{
		"state": "enabled", "executor_kind": "lambda", "executor_lambda": lambdaX,
		"code_execution": "false", "cross_account": "true", "agent": agentARN,
	} {
		if lt.Attributes[k] != v {
			t.Errorf("lambda tool attr %s = %q, want %q", k, lt.Attributes[k], v)
		}
	}
	if !hasLink(s, model.EdgeInvokesTool, agentARN, lambdaTool) {
		t.Error("missing invokes_tool edge to the lambda tool")
	}

	codeTool := agentARN + "/action-group/" + agCode
	ct, ok := nodeOf(s, model.NodeTool, codeTool)
	if !ok {
		t.Fatal("code-interpreter action group not emitted as a tool node")
	}
	if ct.Attributes["code_execution"] != "true" {
		t.Errorf("code_execution = %q, want true for the code interpreter", ct.Attributes["code_execution"])
	}

	// S3 data source: keyed by bucket ARN so it joins the S3 collector's bucket node.
	if _, ok := nodeOf(s, model.NodeDataStore, bucketARN); !ok {
		t.Fatal("S3 data source not emitted as a data_store keyed by bucket ARN")
	}
	if !hasLink(s, model.EdgeAccessesData, agentARN, bucketARN) {
		t.Error("missing accesses_data edge to the S3 bucket")
	}
	// Web data source: external, keyed by a synthetic id.
	webID := "bedrock:datasource:" + kbID + ":" + webDSID
	wd, ok := nodeOf(s, model.NodeDataStore, webID)
	if !ok {
		t.Fatal("web data source not emitted as an external data_store")
	}
	if wd.Attributes["external"] != "true" || wd.Attributes["ds_type"] != "WEB" {
		t.Errorf("web data store attrs = %v, want external/WEB", wd.Attributes)
	}
	if !hasLink(s, model.EdgeAccessesData, agentARN, webID) {
		t.Error("missing accesses_data edge to the external web source")
	}

	for _, svc := range bedrockServices() {
		if c := completenessOf(s, svc); c.Status != collect.Complete {
			t.Errorf("%s = %+v, want complete", svc, c)
		}
	}
}

// TestBedrockCrossAccountFalseSameAccount proves a same-account Lambda executor is not
// flagged cross-account: the fact is derived from the ARN, never assumed.
func TestBedrockCrossAccountFalseSameAccount(t *testing.T) {
	api := oneAgentStub()
	api.actionGroupDetail[agLambda].ActionGroupExecutor = &bedrocktypes.ActionGroupExecutorMemberLambda{Value: lambdaOwn}
	s := runBedrock(t, oneRegion, api)
	lt, _ := nodeOf(s, model.NodeTool, agentARN+"/action-group/"+agLambda)
	if lt.Attributes["cross_account"] != "false" {
		t.Errorf("cross_account = %q, want false for a same-account lambda", lt.Attributes["cross_account"])
	}
}

// TestBedrockReturnControlExecutor proves a RETURN_CONTROL (custom control) executor
// is recorded as custom_control with no lambda and not code execution.
func TestBedrockReturnControlExecutor(t *testing.T) {
	api := oneAgentStub()
	api.actionGroupDetail[agLambda].ActionGroupExecutor = &bedrocktypes.ActionGroupExecutorMemberCustomControl{Value: bedrocktypes.CustomControlMethod("RETURN_CONTROL")}
	s := runBedrock(t, oneRegion, api)
	lt, _ := nodeOf(s, model.NodeTool, agentARN+"/action-group/"+agLambda)
	if lt.Attributes["executor_kind"] != "custom_control" {
		t.Errorf("executor_kind = %q, want custom_control", lt.Attributes["executor_kind"])
	}
	if lt.Attributes["executor_lambda"] != "" {
		t.Errorf("executor_lambda = %q, want empty", lt.Attributes["executor_lambda"])
	}
	if lt.Attributes["cross_account"] != "false" {
		t.Errorf("cross_account = %q, want false", lt.Attributes["cross_account"])
	}
}

// TestBedrockListAgentsDeniedIsGap proves a denied ListAgents is a Denied gap with no
// nodes, never a false empty.
func TestBedrockListAgentsDeniedIsGap(t *testing.T) {
	api := oneAgentStub()
	api.errs = map[string]error{"ListAgents@us-east-1": apiErr("AccessDeniedException")}
	s := runBedrock(t, oneRegion, api)
	if statusOf(s, svcBedrockAgents) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcBedrockAgents, statusOf(s, svcBedrockAgents))
	}
	if nodesByType(s)[model.NodeAIAgent] != 0 {
		t.Error("no agent nodes should be emitted when ListAgents is denied")
	}
	// When the agent listing itself is denied, the per-agent services could not be
	// assessed and must inherit the gap, never be reported complete (live-surfaced fix).
	for _, svc := range []string{svcBedrockActionGroups, svcBedrockKnowledgeBases} {
		if statusOf(s, svc) != collect.Denied {
			t.Errorf("%s = %s, want denied (inherited from the agent listing)", svc, statusOf(s, svc))
		}
	}
}

// TestBedrockGetAgentDeniedIsGap proves a per-agent GetAgent denial is an honest
// coverage gap (Partial), not a silently smaller agent count read as empty.
func TestBedrockGetAgentDeniedIsGap(t *testing.T) {
	api := oneAgentStub()
	api.errs = map[string]error{"GetAgent@us-east-1": apiErr("AccessDeniedException")}
	s := runBedrock(t, oneRegion, api)
	if c := completenessOf(s, svcBedrockAgents); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcBedrockAgents, c)
	}
	if nodesByType(s)[model.NodeAIAgent] != 0 {
		t.Error("an agent with no resolvable ARN must not be emitted")
	}
}

// TestBedrockActionGroupDeniedIsGap proves a denied GetAgentActionGroup is a Partial
// gap on the action-groups service while the agent and its data edges still collect.
func TestBedrockActionGroupDeniedIsGap(t *testing.T) {
	api := oneAgentStub()
	api.errs = map[string]error{"GetAgentActionGroup@us-east-1": apiErr("AccessDeniedException")}
	s := runBedrock(t, oneRegion, api)
	if c := completenessOf(s, svcBedrockActionGroups); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcBedrockActionGroups, c)
	}
	if _, ok := nodeOf(s, model.NodeAIAgent, agentARN); !ok {
		t.Error("agent should still be collected when an action-group read is denied")
	}
	if !hasLink(s, model.EdgeAccessesData, agentARN, bucketARN) {
		t.Error("data edges should still collect when action groups are denied")
	}
}

// TestBedrockRegionNotEnabled proves an opt-in region the account has not enabled is an
// honest Unsupported gap, never a false empty.
func TestBedrockRegionNotEnabled(t *testing.T) {
	api := &stubBedrock{errs: map[string]error{"ListAgents@us-east-1": apiErr("UnrecognizedClientException")}}
	s := runBedrock(t, oneRegion, api)
	if c := completenessOf(s, svcBedrockAgents); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcBedrockAgents, c)
	}
	// A region where the service is not offered must not report the per-agent services
	// complete: they inherit the Unsupported gap (live-surfaced fix).
	for _, svc := range []string{svcBedrockActionGroups, svcBedrockKnowledgeBases} {
		if c := completenessOf(s, svc); c.Status != collect.Unsupported {
			t.Errorf("%s = %+v, want unsupported (inherited from the agent listing)", svc, c)
		}
	}
}

// TestBedrockBudgetExhaustion proves the shared budget bounds the sweep and marks the
// services not reached Partial "budget exhausted".
func TestBedrockBudgetExhaustion(t *testing.T) {
	api := oneAgentStub()
	c := newBedrockAgentsCollector(acctID, api, oneRegion)
	c.budget = collect.NewBudget(1) // ListAgents only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 1 {
		t.Errorf("made %d calls under a 1-call budget; want 1", api.calls)
	}
	for _, svc := range []string{svcBedrockActionGroups, svcBedrockKnowledgeBases} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestBedrockEvidenceRedacts proves the evidence body is scrubbed of a token embedded
// in an agent's instruction (prompt) field.
func TestBedrockEvidenceRedacts(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	api := oneAgentStub()
	api.agentDetail[agentID].Instruction = ptr("use key " + token)
	s := runBedrock(t, oneRegion, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token in %s", e.Operation)
		}
	}
}

// TestBedrockRegionTargeting proves every call is pinned to the declared region.
func TestBedrockRegionTargeting(t *testing.T) {
	api := oneAgentStub()
	_ = runBedrock(t, []string{"eu-west-1"}, api)
	for _, r := range api.regions {
		if r != "eu-west-1" {
			t.Fatalf("a call targeted %q, want eu-west-1", r)
		}
	}
}
