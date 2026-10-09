package collect

import (
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func TestClassifyPolicyAdminEquivalent(t *testing.T) {
	cls, ok := classifyPolicy(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	if !ok || !cls.adminEquivalent || cls.level() != "admin" {
		t.Fatalf("full wildcard not admin: ok=%v cls=%+v level=%s", ok, cls, cls.level())
	}
}

func TestClassifyPolicyDenyIsNotAdmin(t *testing.T) {
	// A Deny of everything plus a narrow Allow is not administrator-equivalent.
	cls, ok := classifyPolicy(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	if !ok {
		t.Fatal("parse failed")
	}
	if cls.adminEquivalent {
		t.Error("a Deny * on * was wrongly read as admin-equivalent")
	}
	if cls.level() != "" {
		t.Errorf("narrow allow classified as %s, want none", cls.level())
	}
}

func TestClassifyPolicyEscalationExactAndWildcard(t *testing.T) {
	exact, _ := classifyPolicy(`{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}}`)
	if exact.level() != "privileged" || !contains(exact.escalation, "iam:passrole") {
		t.Errorf("exact iam:PassRole not privileged: %+v", exact)
	}
	if exact.adminEquivalent {
		t.Error("a single escalation action must not be admin-equivalent")
	}
	wild, _ := classifyPolicy(`{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`)
	if wild.level() != "privileged" || !contains(wild.escalation, "iam:passrole") || !contains(wild.escalation, "iam:putrolepolicy") {
		t.Errorf("iam:* wildcard did not cover escalation actions: %+v", wild)
	}
	if wild.adminEquivalent {
		t.Error("iam:* on * is not full admin (action is not \"*\")")
	}
}

func TestClassifyPolicyNonPrivileged(t *testing.T) {
	cls, ok := classifyPolicy(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`)
	if !ok || cls.level() != "" {
		t.Errorf("read-only policy classified as %s, want none", cls.level())
	}
}

func TestClassifyPolicyURLEncodedAndMalformed(t *testing.T) {
	enc := url.PathEscape(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	if cls, ok := classifyPolicy(enc); !ok || !cls.adminEquivalent {
		t.Error("url-encoded admin document not classified")
	}
	if _, ok := classifyPolicy("not a policy"); ok {
		t.Error("malformed document must return ok=false, not a silent non-privileged result")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"iam:*", "iam:passrole", true},
		{"iam:put*", "iam:putrolepolicy", true},
		{"s3:get*", "iam:passrole", false},
		{"*", "anything", true},
		{"iam:passrole", "iam:passrole", true},
		{"iam:passrole", "iam:createuser", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.s, got, c.want)
		}
	}
}

func TestInlinePrivilegeUnion(t *testing.T) {
	inline := []iamtypes.PolicyDetail{
		{PolicyName: ptr("ro"), PolicyDocument: ptr(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)},
		{PolicyName: ptr("admin"), PolicyDocument: ptr(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)},
	}
	if got := inlinePrivilege(inline); got != "admin" {
		t.Errorf("inline union = %q, want admin (the most privileged member)", got)
	}
}

func TestDefaultPolicyDocumentPicksDefault(t *testing.T) {
	p := iamtypes.ManagedPolicyDetail{
		DefaultVersionId: ptr("v2"),
		PolicyVersionList: []iamtypes.PolicyVersion{
			{VersionId: ptr("v1"), Document: ptr("OLD")},
			{VersionId: ptr("v2"), IsDefaultVersion: true, Document: ptr("NEW")},
		},
	}
	if got := defaultPolicyDocument(p); got != "NEW" {
		t.Errorf("defaultPolicyDocument = %q, want NEW", got)
	}
}

// TestAuthorizationFactsEndToEnd proves the collector emits the privilege facts on
// policy and principal nodes and the trust condition on the assume edge, all from
// the single GetAccountAuthorizationDetails read (no extra API call).
func TestAuthorizationFactsEndToEnd(t *testing.T) {
	adminDoc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	trustWithCond := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}]}`
	api := &stubIAM{
		aliases: &iam.ListAccountAliasesOutput{},
		pages: []*iam.GetAccountAuthorizationDetailsOutput{{
			Policies: []iamtypes.ManagedPolicyDetail{{
				Arn: ptr("arn:aws:iam::123456789012:policy/Admin"), PolicyName: ptr("Admin"), PolicyId: ptr("PID"),
				DefaultVersionId:  ptr("v1"),
				PolicyVersionList: []iamtypes.PolicyVersion{{VersionId: ptr("v1"), IsDefaultVersion: true, Document: ptr(adminDoc)}},
			}},
			RoleDetailList: []iamtypes.RoleDetail{{
				Arn: ptr("arn:aws:iam::123456789012:role/App"), RoleName: ptr("App"),
				AssumeRolePolicyDocument: ptr(trustWithCond),
				RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: ptr("inline"), PolicyDocument: ptr(adminDoc)}},
				PermissionsBoundary:      &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: ptr("arn:aws:iam::123456789012:policy/Boundary")},
			}},
		}},
	}
	scan := run(t, api)

	attrOf := map[string]map[string]string{}
	for _, n := range scan.Nodes {
		attrOf[n.NativeID] = n.Attributes
	}
	if got := attrOf["arn:aws:iam::123456789012:policy/Admin"]["privilege_level"]; got != "admin" {
		t.Errorf("admin policy privilege_level = %q, want admin", got)
	}
	role := attrOf["arn:aws:iam::123456789012:role/App"]
	if role["inline_privilege"] != "admin" {
		t.Errorf("role inline_privilege = %q, want admin", role["inline_privilege"])
	}
	if role["permission_boundary"] != "arn:aws:iam::123456789012:policy/Boundary" {
		t.Errorf("role permission_boundary = %q", role["permission_boundary"])
	}
	// The conditional trust must carry its condition, not be read as unconditional.
	var cond string
	for _, l := range scan.Links {
		if l.TargetNativeID == "arn:aws:iam::123456789012:role/App" && l.Kind == model.EdgeAssumes && l.SourceNativeID == "999999999999" {
			cond = l.Conditions["trust_condition"]
		}
	}
	if cond == "" {
		t.Error("conditional role trust did not carry its trust_condition")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
