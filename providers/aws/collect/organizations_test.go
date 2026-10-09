package collect

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	testOrgArn  = "arn:aws:organizations::111111111111:organization/o-exampleorgid"
	testRootArn = "arn:aws:organizations::111111111111:root/o-exampleorgid/r-root1"
	testOUArn   = "arn:aws:organizations::111111111111:ou/o-exampleorgid/ou-root1-eng"
)

func sp(s string) *string { return &s }

// stubOrg is an offline orgAPI with per-operation error injection.
type stubOrg struct {
	org              *orgtypes.Organization
	roots            []orgtypes.Root
	ousByParent      map[string][]orgtypes.OrganizationalUnit
	accountsByParent map[string][]orgtypes.Account
	errs             map[string]error
	policies         []orgtypes.PolicySummary
	policyContent    map[string]string
	targetsByPolicy  map[string][]orgtypes.PolicyTargetSummary
}

func (s *stubOrg) ListPolicies(_ context.Context, _ *organizations.ListPoliciesInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if e := s.errs["ListPolicies"]; e != nil {
		return nil, e
	}
	return &organizations.ListPoliciesOutput{Policies: s.policies}, nil
}

func (s *stubOrg) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if e := s.errs["DescribePolicy"]; e != nil {
		return nil, e
	}
	content := s.policyContent[*in.PolicyId]
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: sp(content)}}, nil
}

func (s *stubOrg) ListTargetsForPolicy(_ context.Context, in *organizations.ListTargetsForPolicyInput, _ ...func(*organizations.Options)) (*organizations.ListTargetsForPolicyOutput, error) {
	if e := s.errs["ListTargetsForPolicy"]; e != nil {
		return nil, e
	}
	return &organizations.ListTargetsForPolicyOutput{Targets: s.targetsByPolicy[*in.PolicyId]}, nil
}

func (s *stubOrg) DescribeOrganization(_ context.Context, _ *organizations.DescribeOrganizationInput, _ ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if e := s.errs["DescribeOrganization"]; e != nil {
		return nil, e
	}
	return &organizations.DescribeOrganizationOutput{Organization: s.org}, nil
}

func (s *stubOrg) ListRoots(_ context.Context, _ *organizations.ListRootsInput, _ ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if e := s.errs["ListRoots"]; e != nil {
		return nil, e
	}
	return &organizations.ListRootsOutput{Roots: s.roots}, nil
}

func (s *stubOrg) ListOrganizationalUnitsForParent(_ context.Context, in *organizations.ListOrganizationalUnitsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	if e := s.errs["ListOrganizationalUnitsForParent"]; e != nil {
		return nil, e
	}
	return &organizations.ListOrganizationalUnitsForParentOutput{OrganizationalUnits: s.ousByParent[*in.ParentId]}, nil
}

func (s *stubOrg) ListAccountsForParent(_ context.Context, in *organizations.ListAccountsForParentInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error) {
	if e := s.errs["ListAccountsForParent"]; e != nil {
		return nil, e
	}
	return &organizations.ListAccountsForParentOutput{Accounts: s.accountsByParent[*in.ParentId]}, nil
}

func orgStub() *stubOrg {
	return &stubOrg{
		org:   &orgtypes.Organization{Id: sp("o-exampleorgid"), Arn: sp(testOrgArn), FeatureSet: orgtypes.OrganizationFeatureSetAll, MasterAccountId: sp("111111111111")},
		roots: []orgtypes.Root{{Id: sp("r-root1"), Arn: sp(testRootArn), Name: sp("Root")}},
		ousByParent: map[string][]orgtypes.OrganizationalUnit{
			"r-root1": {{Id: sp("ou-root1-eng"), Arn: sp(testOUArn), Name: sp("Engineering")}},
		},
		accountsByParent: map[string][]orgtypes.Account{
			"r-root1":      {{Id: sp("111111111111"), Name: sp("Management"), Status: orgtypes.AccountStatusActive, Email: sp("root@example.com")}},
			"ou-root1-eng": {{Id: sp("222222222222"), Name: sp("Dev"), Status: orgtypes.AccountStatusActive, Email: sp("dev@example.com")}},
		},
	}
}

func runOrg(t *testing.T, account string, api orgAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newOrganizationsCollector(account, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func orgNode(s collect.Scan, tp model.NodeType, id string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == tp && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestOrganizationsWalksTree proves the walk emits the organization, its root, each
// organizational unit, and each member account, with ARNs for the containers, the
// 12-digit account id for accounts (so they merge with the IAM node), each carrying its
// parent as a forward-key id fact, and no account email (PII).
func TestOrganizationsWalksTree(t *testing.T) {
	s := runOrg(t, "111111111111", orgStub())

	org, ok := orgNode(s, model.NodeOrganization, testOrgArn)
	if !ok {
		t.Fatal("organization not keyed by its arn")
	}
	for k, want := range map[string]string{
		"hierarchy_type": "organization", "organization_id": "o-exampleorgid",
		"master_account_id": "111111111111", "feature_set": "ALL",
	} {
		if org.Attributes[k] != want {
			t.Errorf("org %s = %q, want %q", k, org.Attributes[k], want)
		}
	}
	if _, has := org.Attributes["parent_id"]; has {
		t.Errorf("organization must have no parent_id")
	}

	if root, ok := orgNode(s, model.NodeOrganization, testRootArn); !ok {
		t.Fatal("root not emitted")
	} else if root.Attributes["hierarchy_type"] != "organizational_root" || root.Attributes["parent_id"] != testOrgArn {
		t.Errorf("root attrs = %+v", root.Attributes)
	}

	if ou, ok := orgNode(s, model.NodeOrganization, testOUArn); !ok {
		t.Fatal("OU not emitted")
	} else if ou.Attributes["hierarchy_type"] != "organizational_unit" || ou.Attributes["parent_id"] != testRootArn {
		t.Errorf("OU attrs = %+v", ou.Attributes)
	}

	mgmt, ok := orgNode(s, model.NodeAccount, "111111111111")
	if !ok {
		t.Fatal("management account not keyed by its 12-digit id (would not merge with the IAM node)")
	}
	if mgmt.Attributes["parent_id"] != testRootArn || mgmt.Attributes["status"] != "ACTIVE" {
		t.Errorf("management account attrs = %+v", mgmt.Attributes)
	}

	dev, ok := orgNode(s, model.NodeAccount, "222222222222")
	if !ok {
		t.Fatal("dev account not emitted")
	}
	if dev.Attributes["parent_id"] != testOUArn {
		t.Errorf("dev account parent_id = %q, want %q", dev.Attributes["parent_id"], testOUArn)
	}
	for _, forbidden := range []string{"email", "compliant"} {
		if _, bad := dev.Attributes[forbidden]; bad {
			t.Errorf("account must not carry a %q attribute", forbidden)
		}
	}
	if c := completenessOf(s, "organizations.hierarchy"); c.Status != collect.Complete || c.Collected != 5 {
		t.Errorf("organizations.hierarchy = %+v, want complete/5", c)
	}
}

// TestOrganizationsNotInUse proves an account that is not a member of any organization
// is recorded as an explicit fact (Complete with a stated reason), not a Denied or
// Errored gap, and emits no node.
func TestOrganizationsNotInUse(t *testing.T) {
	api := &stubOrg{errs: map[string]error{"DescribeOrganization": &orgtypes.AWSOrganizationsNotInUseException{}}}
	s := runOrg(t, "111111111111", api)
	c := completenessOf(s, "organizations.hierarchy")
	if c.Status != collect.Complete {
		t.Errorf("status = %s, want complete (not in an org is a fact, not a gap)", c.Status)
	}
	if c.Reason != "account is not a member of an organization" {
		t.Errorf("reason = %q", c.Reason)
	}
	if len(s.Nodes) != 0 {
		t.Errorf("nodes = %d, want 0", len(s.Nodes))
	}
}

// TestOrganizationsDeniedIsGap proves a denied DescribeOrganization is a Denied gap
// (never a pass), emitting no node.
func TestOrganizationsDeniedIsGap(t *testing.T) {
	api := &stubOrg{errs: map[string]error{"DescribeOrganization": &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no"}}}
	s := runOrg(t, "111111111111", api)
	if statusOf(s, "organizations.hierarchy") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "organizations.hierarchy"))
	}
	if len(s.Nodes) != 0 {
		t.Errorf("nodes = %d, want 0", len(s.Nodes))
	}
}

// TestOrganizationsSubReadDeniedIsPartial proves that when the organization reads but a
// child list is denied, the organization node stands and the record is Partial, never
// Complete and never an inferred tree.
func TestOrganizationsSubReadDeniedIsPartial(t *testing.T) {
	api := orgStub()
	api.errs = map[string]error{"ListRoots": &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no"}}
	s := runOrg(t, "111111111111", api)
	if _, ok := orgNode(s, model.NodeOrganization, testOrgArn); !ok {
		t.Error("organization must still be emitted when a child list is denied")
	}
	if statusOf(s, "organizations.hierarchy") != collect.Partial {
		t.Errorf("status = %s, want partial", statusOf(s, "organizations.hierarchy"))
	}
}

// TestOrganizationsEvidenceHasNoSecret proves the evidence envelopes carry no response
// body (the collector records operation provenance only, never account emails).
func TestOrganizationsEvidenceHasNoSecret(t *testing.T) {
	s := runOrg(t, "111111111111", orgStub())
	for _, e := range s.Envelopes {
		if len(e.Response) != 0 {
			t.Errorf("organizations evidence must carry no response body, got %q", string(e.Response))
		}
	}
}
