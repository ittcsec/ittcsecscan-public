package collect

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// A role that federates trust to GitHub Actions via OIDC yields both the assumes edge
// from the OIDC provider and a cross-domain federates_with edge from the named GitHub
// repository (keyed by owner/repo) to the role (ADR-0031 EX-2b).
func TestGitHubOIDCFederationEdge(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/Deploy"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:ittcsec/ittcsecscan:*"}}}]}`
	var scan collect.Scan
	(&IdentityCollector{}).trustEdges(&scan, role, doc)

	fed := false
	for _, l := range scan.Links {
		if l.Kind == model.EdgeFederatesWith && l.SourceNativeID == "ittcsec/ittcsecscan" && l.TargetNativeID == role {
			fed = true
		}
	}
	if !fed {
		t.Fatalf("expected a federates_with edge ittcsec/ittcsecscan -> role, got %+v", scan.Links)
	}
}

// A non-GitHub federated principal (or a GitHub trust with no repo in its sub claim)
// yields no federates_with edge; the repo is never guessed.
func TestNonGitHubFederationEmitsNoRepoEdge(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/SAML"
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML"}]}`
	var scan collect.Scan
	(&IdentityCollector{}).trustEdges(&scan, role, doc)
	for _, l := range scan.Links {
		if l.Kind == model.EdgeFederatesWith {
			t.Errorf("unexpected federates_with edge for a non-github federation: %+v", l)
		}
	}
}

// A role that federates trust to GitLab CI/CD via OIDC yields a cross-domain
// federates_with edge from the named GitLab project (keyed group/project) to the role
// (ADR-0031 GL-4).
func TestGitLabOIDCFederationEdge(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/Deploy"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"https://gitlab.com"},"StringLike":{"gitlab.com:sub":"project_path:acme/infra/deployer:ref_type:branch:ref:main"}}}]}`
	var scan collect.Scan
	(&IdentityCollector{}).trustEdges(&scan, role, doc)

	fed := false
	for _, l := range scan.Links {
		if l.Kind == model.EdgeFederatesWith && l.SourceNativeID == "acme/infra/deployer" && l.TargetNativeID == role {
			fed = true
		}
	}
	if !fed {
		t.Fatalf("expected a federates_with edge acme/infra/deployer -> role, got %+v", scan.Links)
	}
}

func TestProjectFromSub(t *testing.T) {
	cases := map[string]string{
		"project_path:acme/web:ref_type:branch:ref:main": "acme/web",
		"project_path:group/subgroup/proj:*":             "group/subgroup/proj",
		"project_path:group/proj":                        "group/proj",
		"project_path:noslash:*":                         "",
		"project_id:42:ref_type:branch":                  "",
		"repo:acme/web:*":                                "",
	}
	for sub, want := range cases {
		got, ok := projectFromSub(sub)
		if want == "" && ok {
			t.Errorf("projectFromSub(%q) = %q, want no match", sub, got)
		}
		if want != "" && got != want {
			t.Errorf("projectFromSub(%q) = %q, want %q", sub, got, want)
		}
	}
}

func TestRepoFromSub(t *testing.T) {
	cases := map[string]string{
		"repo:ittcsec/ittcsecscan:ref:refs/heads/main": "ittcsec/ittcsecscan",
		"repo:acme/web:*":    "acme/web",
		"repo:acme/web":      "acme/web",
		"repo:noslash:*":     "",
		"job_workflow_ref:x": "",
	}
	for sub, want := range cases {
		got, ok := repoFromSub(sub)
		if want == "" && ok {
			t.Errorf("repoFromSub(%q) = %q, want no match", sub, got)
		}
		if want != "" && got != want {
			t.Errorf("repoFromSub(%q) = %q, want %q", sub, got, want)
		}
	}
}

func findNode(nodes []collect.Node, nativeID string) (collect.Node, bool) {
	for _, n := range nodes {
		if n.NativeID == nativeID {
			return n, true
		}
	}
	return collect.Node{}, false
}

func findLink(links []collect.Link, source, target string) (collect.Link, bool) {
	for _, l := range links {
		if l.SourceNativeID == source && l.TargetNativeID == target {
			return l, true
		}
	}
	return collect.Link{}, false
}

// A role trusted by an AI-runtime service principal (Bedrock) yields an ai_agent node and
// an assumes edge from that runtime to the role, the evidence-only AI-agent trust
// relationship (ADR-0031, AI domain). A non-AI service principal stays a service node.
func TestAIRuntimeTrustEmitsAIAgent(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/BedrockExec"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	var scan collect.Scan
	(&IdentityCollector{}).trustEdges(&scan, role, doc)

	agent, ok := findNode(scan.Nodes, "bedrock.amazonaws.com")
	if !ok || agent.Type != model.NodeAIAgent || agent.Attributes["ai_runtime"] != "bedrock" {
		t.Fatalf("expected an ai_agent node for the Bedrock runtime, got %+v", agent)
	}
	if _, ok := findLink(scan.Links, "bedrock.amazonaws.com", role); !ok {
		t.Fatalf("expected an assumes edge ai_agent -> role, got %+v", scan.Links)
	}
	// A non-AI service principal is still a plain service node.
	var scan2 collect.Scan
	(&IdentityCollector{}).trustEdges(&scan2, role, `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	if n, _ := findNode(scan2.Nodes, "ec2.amazonaws.com"); n.Type != model.NodeService {
		t.Errorf("ec2 service principal should be a service node, got %s", n.Type)
	}
}

func TestAIRuntimeName(t *testing.T) {
	if n, ok := aiRuntimeName("bedrock.amazonaws.com"); !ok || n != "bedrock" {
		t.Errorf("bedrock not recognized: %q %v", n, ok)
	}
	if _, ok := aiRuntimeName("ec2.amazonaws.com"); ok {
		t.Error("ec2 must not be an AI runtime")
	}
}

func TestTrustedPrincipals(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com","AWS":["arn:aws:iam::999999999999:root","arn:aws:iam::123456789012:user/Alice"]},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::555555555555:root"},"Action":"sts:AssumeRole"}]}`
	ps := trustedPrincipals(doc)
	got := map[string]string{}
	for _, p := range ps {
		got[p.value] = p.typ
	}
	if got["ec2.amazonaws.com"] != "service" {
		t.Errorf("service principal not parsed: %v", ps)
	}
	if got["arn:aws:iam::999999999999:root"] != "aws" || got["arn:aws:iam::123456789012:user/Alice"] != "aws" {
		t.Errorf("aws principals not parsed: %v", ps)
	}
	if _, denied := got["arn:aws:iam::555555555555:root"]; denied {
		t.Error("a Deny statement's principal must not be a trust edge")
	}
}

func TestTrustedPrincipalsStarAndSingleStatement(t *testing.T) {
	// Principal "*" as a string, and Statement as a single object (not an array).
	star := trustedPrincipals(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	if len(star) != 1 || star[0].value != "*" {
		t.Fatalf("star principal not parsed: %v", star)
	}
	// {"AWS":"*"} is equally public.
	awsStar := trustedPrincipals(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`)
	if len(awsStar) != 1 || awsStar[0].value != "*" {
		t.Fatalf("AWS:* not parsed: %v", awsStar)
	}
}

func TestTrustedPrincipalsURLEncoded(t *testing.T) {
	// A document with a URL-encoded space (%20), as the IAM API returns it.
	doc := `{"Statement":[{"Effect":%20"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	ps := trustedPrincipals(doc)
	if len(ps) != 1 || ps[0].value != "lambda.amazonaws.com" {
		t.Fatalf("URL-encoded doc not decoded/parsed: %v", ps)
	}
}

func TestPrincipalNode(t *testing.T) {
	cases := []struct {
		p      trustPrincipal
		typ    model.NodeType
		native string
		public bool
	}{
		{trustPrincipal{"aws", "arn:aws:iam::123456789012:root"}, model.NodeAccount, "123456789012", false},
		{trustPrincipal{"aws", "123456789012"}, model.NodeAccount, "123456789012", false},
		{trustPrincipal{"aws", "arn:aws:iam::123456789012:role/App"}, model.NodeRole, "arn:aws:iam::123456789012:role/App", false},
		{trustPrincipal{"aws", "arn:aws:iam::123456789012:user/Alice"}, model.NodeIdentity, "arn:aws:iam::123456789012:user/Alice", false},
		{trustPrincipal{"aws", "*"}, model.NodeIdentity, "*", true},
		{trustPrincipal{"service", "ec2.amazonaws.com"}, model.NodeService, "ec2.amazonaws.com", false},
		{trustPrincipal{"federated", "arn:aws:iam::123456789012:saml-provider/Corp"}, model.NodeIdentity, "arn:aws:iam::123456789012:saml-provider/Corp", false},
	}
	for _, tc := range cases {
		n, ok := principalNode(tc.p)
		if !ok || n.Type != tc.typ || n.NativeID != tc.native {
			t.Errorf("principalNode(%+v) = (%s, %q, %v), want (%s, %q)", tc.p, n.Type, n.NativeID, ok, tc.typ, tc.native)
		}
		if tc.public && n.Attributes["public"] != "true" {
			t.Errorf("principalNode(%+v) not marked public", tc.p)
		}
	}
}

// TestIdentityCollectorEmitsAuthorizationEdges proves the collector emits policy
// attachment and role-trust edges (both EdgeAssumes) from the single
// GetAccountAuthorizationDetails read, and that attached policies and trusted
// principals are nodes so the edges resolve.
func TestIdentityCollectorEmitsAuthorizationEdges(t *testing.T) {
	roleTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com","AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`
	api := &stubIAM{
		aliases: &iam.ListAccountAliasesOutput{},
		pages: []*iam.GetAccountAuthorizationDetailsOutput{{
			IsTruncated: false,
			UserDetailList: []iamtypes.UserDetail{{
				Arn: ptr("arn:aws:iam::123456789012:user/Alice"), UserName: ptr("Alice"),
				AttachedManagedPolicies: []iamtypes.AttachedPolicy{{PolicyName: ptr("S3Read"), PolicyArn: ptr("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")}},
			}},
			RoleDetailList: []iamtypes.RoleDetail{{
				Arn: ptr("arn:aws:iam::123456789012:role/App"), RoleName: ptr("App"),
				AssumeRolePolicyDocument: ptr(roleTrust),
				AttachedManagedPolicies:  []iamtypes.AttachedPolicy{{PolicyName: ptr("DDB"), PolicyArn: ptr("arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess")}},
			}},
		}},
	}
	scan := run(t, api)

	links := map[string]string{} // source|target -> kind
	for _, l := range scan.Links {
		links[l.SourceNativeID+"|"+l.TargetNativeID] = string(l.Kind)
	}
	// Policy attachments (assumes): user and role each to their managed policy.
	if links["arn:aws:iam::123456789012:user/Alice|arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"] != string(model.EdgeAssumes) {
		t.Error("missing user policy-attachment edge")
	}
	if links["arn:aws:iam::123456789012:role/App|arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"] != string(model.EdgeAssumes) {
		t.Error("missing role policy-attachment edge")
	}
	// Role trust (assumes): the service and the external account root can assume.
	if links["ec2.amazonaws.com|arn:aws:iam::123456789012:role/App"] != string(model.EdgeAssumes) {
		t.Error("missing service trust edge")
	}
	if links["999999999999|arn:aws:iam::123456789012:role/App"] != string(model.EdgeAssumes) {
		t.Error("missing external-account trust edge")
	}

	// The attached AWS-managed policy and the service principal must be nodes so
	// the edges resolve.
	byType := map[model.NodeType]map[string]bool{}
	for _, n := range scan.Nodes {
		if byType[n.Type] == nil {
			byType[n.Type] = map[string]bool{}
		}
		byType[n.Type][n.NativeID] = true
	}
	if !byType[model.NodePolicy]["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"] {
		t.Error("attached managed policy was not emitted as a node")
	}
	if !byType[model.NodeService]["ec2.amazonaws.com"] {
		t.Error("service principal was not emitted as a node")
	}
	if !byType[model.NodeAccount]["999999999999"] {
		t.Error("external account root was not emitted as a node")
	}
}
