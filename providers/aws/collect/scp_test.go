package collect

import (
	"testing"

	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

func TestScpDenyLevel(t *testing.T) {
	if lvl := scpDenyLevel(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`); lvl != "admin" {
		t.Errorf("Deny * => %q, want admin", lvl)
	}
	if lvl := scpDenyLevel(`{"Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`); lvl != "privileged" {
		t.Errorf("Deny iam:PassRole => %q, want privileged", lvl)
	}
	// FullAWSAccess (Allow *, no Deny) is not a cap.
	if lvl := scpDenyLevel(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`); lvl != "" {
		t.Errorf("an allow-only SCP => %q, want none (not a cap)", lvl)
	}
	// A deny of a non-privileged action removes no privilege level.
	if lvl := scpDenyLevel(`{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`); lvl != "" {
		t.Errorf("Deny s3:DeleteObject => %q, want none", lvl)
	}
}

// TestScpStampsAccountTarget proves an SCP that denies everything, attached to an
// account, stamps deny_privilege_level=admin on that account node (keyed by account
// id, so the Step 4 engine applies the cap to every principal in the account), with
// organizations.scps reported Complete.
func TestScpStampsAccountTarget(t *testing.T) {
	api := orgStub()
	api.policies = []orgtypes.PolicySummary{{Id: sp("p-scp1"), Name: sp("DenyAll")}}
	api.policyContent = map[string]string{"p-scp1": `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`}
	api.targetsByPolicy = map[string][]orgtypes.PolicyTargetSummary{
		"p-scp1": {{TargetId: sp("222222222222"), Type: orgtypes.TargetTypeAccount}},
	}
	s := runOrg(t, "111111111111", api)

	var stamped bool
	for _, n := range s.Nodes {
		if n.NativeID == "222222222222" && n.Attributes["deny_privilege_level"] == "admin" {
			stamped = true
		}
	}
	if !stamped {
		t.Error("SCP did not stamp deny_privilege_level=admin on the targeted account")
	}
	if statusOf(s, "organizations.scps") != collect.Complete {
		t.Errorf("organizations.scps status = %s, want complete", statusOf(s, "organizations.scps"))
	}
}

// TestScpAllowOnlyNotStamped proves an allow-only SCP (no Deny) stamps nothing.
func TestScpAllowOnlyNotStamped(t *testing.T) {
	api := orgStub()
	api.policies = []orgtypes.PolicySummary{{Id: sp("p-full"), Name: sp("FullAWSAccess")}}
	api.policyContent = map[string]string{"p-full": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
	api.targetsByPolicy = map[string][]orgtypes.PolicyTargetSummary{
		"p-full": {{TargetId: sp("222222222222"), Type: orgtypes.TargetTypeAccount}},
	}
	s := runOrg(t, "111111111111", api)
	for _, n := range s.Nodes {
		if _, has := n.Attributes["deny_privilege_level"]; has {
			t.Errorf("an allow-only SCP wrongly stamped a cap on %s", n.NativeID)
		}
	}
}
