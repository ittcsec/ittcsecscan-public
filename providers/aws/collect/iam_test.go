package collect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/schema"
)

func ptr(s string) *string { return &s }

// stubIAM returns canned pages and errors, so the collector is tested with no
// network and no real SDK.
type stubIAM struct {
	pages    []*iam.GetAccountAuthorizationDetailsOutput
	pageErr  error
	aliases  *iam.ListAccountAliasesOutput
	aliasErr error
	call     int
}

func (s *stubIAM) GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if s.pageErr != nil {
		return nil, s.pageErr
	}
	out := s.pages[s.call]
	s.call++
	return out, nil
}

func (s *stubIAM) ListAccountAliases(context.Context, *iam.ListAccountAliasesInput, ...func(*iam.Options)) (*iam.ListAccountAliasesOutput, error) {
	if s.aliasErr != nil {
		return nil, s.aliasErr
	}
	return s.aliases, nil
}

func apiErr(code string) error { return &smithy.GenericAPIError{Code: code, Message: "m"} }

func run(t *testing.T, api identityAPI) *collect.Scan {
	t.Helper()
	var scan collect.Scan
	if err := collect.Run(context.Background(), []collect.Collector{newIdentityCollector("123456789012", api)}, &scan); err != nil {
		t.Fatalf("run: %v", err)
	}
	return &scan
}

// TestIdentityCollectorBudgetExhaustion proves the shared call budget bites: with
// only enough budget for the alias read, the identity enumeration is a recorded
// Partial "budget exhausted" gap and its API call is never made.
func TestIdentityCollectorBudgetExhaustion(t *testing.T) {
	api := &stubIAM{
		aliases: &iam.ListAccountAliasesOutput{AccountAliases: []string{"acme"}},
		pages:   []*iam.GetAccountAuthorizationDetailsOutput{{IsTruncated: false}},
	}
	c := newIdentityCollector("123456789012", api)
	c.budget = collect.NewBudget(1) // enough for the alias read, not the identities read

	var scan collect.Scan
	if err := c.Collect(context.Background(), &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var identities collect.Completeness
	found := false
	for _, comp := range scan.Completeness {
		if comp.Service == "iam.identities" {
			identities, found = comp, true
		}
	}
	if !found || identities.Status != collect.Partial || identities.Reason != "budget exhausted" {
		t.Fatalf("iam.identities not a budget-exhausted Partial: %+v", identities)
	}
	if api.call != 0 {
		t.Errorf("GetAccountAuthorizationDetails called %d times under an exhausted budget; want 0", api.call)
	}
}

func TestIdentityCollectorBuildsTheGraph(t *testing.T) {
	api := &stubIAM{
		aliases: &iam.ListAccountAliasesOutput{AccountAliases: []string{"example-corp"}},
		pages: []*iam.GetAccountAuthorizationDetailsOutput{
			{
				IsTruncated: true, Marker: ptr("m1"),
				UserDetailList:  []iamtypes.UserDetail{{Arn: ptr("arn:aws:iam::123456789012:user/Alice"), UserName: ptr("Alice"), UserId: ptr("AIDAALICE"), Path: ptr("/"), GroupList: []string{"Admins"}}},
				GroupDetailList: []iamtypes.GroupDetail{{Arn: ptr("arn:aws:iam::123456789012:group/Admins"), GroupName: ptr("Admins"), GroupId: ptr("AGPADMINS")}},
			},
			{
				IsTruncated:    false,
				RoleDetailList: []iamtypes.RoleDetail{{Arn: ptr("arn:aws:iam::123456789012:role/Scanner"), RoleName: ptr("Scanner"), RoleId: ptr("AROASCAN")}},
				Policies:       []iamtypes.ManagedPolicyDetail{{Arn: ptr("arn:aws:iam::aws:policy/ReadOnlyAccess"), PolicyName: ptr("ReadOnlyAccess"), PolicyId: ptr("ANPARO")}},
			},
		},
	}
	scan := run(t, api)

	// The account node is named from the alias, and every identity kind is a node.
	types := map[model.NodeType]int{}
	var accountName string
	for _, n := range scan.Nodes {
		types[n.Type]++
		if n.Type == model.NodeAccount {
			accountName = n.Name
		}
	}
	if accountName != "example-corp" {
		t.Errorf("account name = %q, want example-corp", accountName)
	}
	for _, want := range []model.NodeType{model.NodeAccount, model.NodeIdentity, model.NodeRole, model.NodeGroup, model.NodePolicy} {
		if types[want] == 0 {
			t.Errorf("no %s node emitted; nodes=%+v", want, scan.Nodes)
		}
	}
	// The membership link joins the user to the group node by ARN.
	found := false
	for _, l := range scan.Links {
		if l.Kind == model.EdgeMemberOf && l.SourceNativeID == "arn:aws:iam::123456789012:user/Alice" && l.TargetNativeID == "arn:aws:iam::123456789012:group/Admins" {
			found = true
		}
	}
	if !found {
		t.Errorf("no user->group membership link joining to the group ARN: %+v", scan.Links)
	}
	// Both pages produced evidence, and the enumeration is Complete.
	if len(scan.Envelopes) < 2 {
		t.Errorf("want an evidence envelope per read, got %d", len(scan.Envelopes))
	}
	if !scan.Full() {
		t.Errorf("a clean two-page read should be Full: %+v", scan.Completeness)
	}
}

func TestIdentityCollectorDeniedIsNotEmpty(t *testing.T) {
	api := &stubIAM{aliases: &iam.ListAccountAliasesOutput{}, pageErr: apiErr("AccessDenied")}
	scan := run(t, api)
	// A denied enumeration is Denied, never Complete: the account is not reported
	// as having no identities.
	var got collect.Completeness
	for _, c := range scan.Completeness {
		if c.Service == "iam.identities" {
			got = c
		}
	}
	if got.Status != collect.Denied || got.Done() {
		t.Fatalf("denied read not represented as a gap: %+v", scan.Completeness)
	}
}

func TestIdentityCollectorThrottleIsPartial(t *testing.T) {
	api := &stubIAM{aliases: &iam.ListAccountAliasesOutput{}, pageErr: apiErr("Throttling")}
	scan := run(t, api)
	var got collect.Completeness
	for _, c := range scan.Completeness {
		if c.Service == "iam.identities" {
			got = c
		}
	}
	if got.Status != collect.Partial {
		t.Fatalf("throttled read not Partial: %+v", scan.Completeness)
	}
}

// TestIdentityCollectorEvidenceMatchesSchema proves the collector's evidence
// satisfies the published envelope schema and carries no leaked token.
func TestIdentityCollectorEvidenceMatchesSchema(t *testing.T) {
	api := &stubIAM{
		aliases: &iam.ListAccountAliasesOutput{AccountAliases: []string{"acme"}},
		pages:   []*iam.GetAccountAuthorizationDetailsOutput{{IsTruncated: false}},
	}
	scan := run(t, api)
	if len(scan.Envelopes) == 0 {
		t.Fatal("no evidence emitted")
	}
	for _, e := range scan.Envelopes {
		if err := schema.ValidateValue(schema.CollectEnvelope, e); err != nil {
			t.Fatalf("evidence does not match schema: %v", err)
		}
	}
}

// TestUnexpectedErrorSurfaces proves a non-denied error is reported by Run, not
// silently swallowed.
func TestUnexpectedErrorSurfaces(t *testing.T) {
	api := &stubIAM{aliases: &iam.ListAccountAliasesOutput{}, pageErr: errors.New("connection reset")}
	var scan collect.Scan
	err := collect.Run(context.Background(), []collect.Collector{newIdentityCollector("123456789012", api)}, &scan)
	if err == nil || !strings.Contains(err.Error(), identityCollectorID) {
		t.Fatalf("unexpected error not surfaced by Run: %v", err)
	}
}

// TestIAMRoleLastUsed proves the role nodes carry the RoleLastUsed dormancy signal: a
// role used recently records the date, region, and a numeric age-in-days (against a
// fixed clock); a role with no activity in the tracking window records role_last_used
// "never"; and a service-linked role (by /aws-service-role/ path) is flagged so a
// dormancy rule can exclude it.
func TestIAMRoleLastUsed(t *testing.T) {
	used := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	api := &stubIAM{aliases: &iam.ListAccountAliasesOutput{AccountAliases: []string{"acme"}}, pages: []*iam.GetAccountAuthorizationDetailsOutput{{RoleDetailList: []iamtypes.RoleDetail{
		{Arn: ptr("arn:aws:iam::123456789012:role/Active"), RoleName: ptr("Active"), RoleId: ptr("AROAA"), Path: ptr("/"),
			RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &used, Region: ptr("us-east-1")}},
		{Arn: ptr("arn:aws:iam::123456789012:role/Dormant"), RoleName: ptr("Dormant"), RoleId: ptr("AROAD"), Path: ptr("/")},
		{Arn: ptr("arn:aws:iam::123456789012:role/aws-service-role/x/SLR"), RoleName: ptr("SLR"), RoleId: ptr("AROAS"), Path: ptr("/aws-service-role/x/")},
	}}}}
	c := newIdentityCollector("123456789012", api)
	c.now = func() time.Time { return time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) }
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	byID := map[string]collect.Node{}
	for _, n := range s.Nodes {
		byID[n.NativeID] = n
	}
	active := byID["arn:aws:iam::123456789012:role/Active"]
	if active.Attributes["role_last_used"] != "2026-09-01T00:00:00Z" || active.Attributes["role_last_used_region"] != "us-east-1" {
		t.Errorf("active role last-used = %q / %q", active.Attributes["role_last_used"], active.Attributes["role_last_used_region"])
	}
	// 2026-09-01 to 2026-10-05 is 34 days.
	if active.Attributes["role_last_used_age_days"] != "34" || active.Attributes["service_linked"] != "false" {
		t.Errorf("active role age/service-linked = %q / %q", active.Attributes["role_last_used_age_days"], active.Attributes["service_linked"])
	}
	dormant := byID["arn:aws:iam::123456789012:role/Dormant"]
	if dormant.Attributes["role_last_used"] != "never" || dormant.Attributes["role_last_used_age_days"] != "" {
		t.Errorf("dormant role last-used = %q age=%q, want never / no age", dormant.Attributes["role_last_used"], dormant.Attributes["role_last_used_age_days"])
	}
	slr := byID["arn:aws:iam::123456789012:role/aws-service-role/x/SLR"]
	if slr.Attributes["service_linked"] != "true" {
		t.Errorf("service-linked role service_linked = %q, want true", slr.Attributes["service_linked"])
	}
}
