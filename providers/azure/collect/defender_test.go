package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	vmPlanID       = "/subscriptions/sub-1/providers/Microsoft.Security/pricings/VirtualMachines"
	posturePlanID  = "/subscriptions/sub-1/providers/Microsoft.Security/pricings/CloudPosture"
	autoProvSettID = "/subscriptions/sub-1/providers/Microsoft.Security/autoProvisioningSettings/default"
)

// twoPricings is a pricings list page (no nextLink): the VirtualMachines plan on the
// Standard tier and CloudPosture on Free.
const twoPricings = `{"value":[
	{"id":"` + vmPlanID + `","name":"VirtualMachines","type":"Microsoft.Security/pricings",
	 "properties":{"pricingTier":"Standard","subPlan":"P2","enforce":"False","enablementTime":"2023-03-01T12:42:42Z"}},
	{"id":"` + posturePlanID + `","name":"CloudPosture","type":"Microsoft.Security/pricings",
	 "properties":{"pricingTier":"Free"}}
]}`

// oneAutoProvisioning is an autoProvisioningSettings list page: the default setting On.
const oneAutoProvisioning = `{"value":[
	{"id":"` + autoProvSettID + `","name":"default","type":"Microsoft.Security/autoProvisioningSettings",
	 "properties":{"autoProvision":"On"}}
]}`

func defenderStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?":          subsOne,
		"pricings":                 twoPricings,
		"autoProvisioningSettings": oneAutoProvisioning,
	}}
}

func runDefender(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newDefenderCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestDefenderPricings proves each Defender plan becomes a control node keyed by its
// ARM resource id with its pricing tier recorded as a fact, and no enabled/disabled
// verdict synthesized.
func TestDefenderPricings(t *testing.T) {
	s := runDefender(t, defenderStub())

	vm, ok := nodeNamed(s, model.NodeControl, vmPlanID)
	if !ok {
		t.Fatal("VirtualMachines plan not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "defender_plan", "plan": "VirtualMachines", "pricing_tier": "Standard",
		"sub_plan": "P2", "enforce": "False",
	} {
		if vm.Attributes[k] != want {
			t.Errorf("VirtualMachines %s = %q, want %q", k, vm.Attributes[k], want)
		}
	}
	posture, ok := nodeNamed(s, model.NodeControl, posturePlanID)
	if !ok {
		t.Fatal("CloudPosture plan not emitted")
	}
	if posture.Attributes["pricing_tier"] != "Free" {
		t.Errorf("CloudPosture pricing_tier = %q, want Free", posture.Attributes["pricing_tier"])
	}
	for _, forbidden := range []string{"enabled", "protected", "compliant"} {
		if _, bad := vm.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "defender.pricings"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("defender.pricings = %+v, want complete/2", c)
	}
}

// TestDefenderAutoProvisioning proves the auto-provisioning setting maps to a control
// node with its On/Off state.
func TestDefenderAutoProvisioning(t *testing.T) {
	s := runDefender(t, defenderStub())

	n, ok := nodeNamed(s, model.NodeControl, autoProvSettID)
	if !ok {
		t.Fatal("auto-provisioning setting not emitted")
	}
	if n.Attributes["azure_type"] != "auto_provisioning_setting" || n.Attributes["auto_provision"] != "On" {
		t.Errorf("auto-provisioning = %q/%q, want auto_provisioning_setting/On", n.Attributes["azure_type"], n.Attributes["auto_provision"])
	}
}

// TestDefenderDeniedIsGap proves a denied pricings read is a Denied gap that does not
// fail the run and does not block auto-provisioning.
func TestDefenderDeniedIsGap(t *testing.T) {
	api := defenderStub()
	api.failSub = "pricings"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newDefenderCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "defender.pricings") != collect.Denied {
		t.Errorf("defender.pricings = %s, want denied", statusOf(s, "defender.pricings"))
	}
	if _, ok := nodeNamed(s, model.NodeControl, vmPlanID); ok {
		t.Error("a denied pricings read must not emit a plan node")
	}
	if statusOf(s, "defender.autoProvisioning") != collect.Complete {
		t.Errorf("auto-provisioning should still be complete, got %s", statusOf(s, "defender.autoProvisioning"))
	}
}

// TestDefenderEmptyIsComplete proves an empty subscription is an honest Complete/0.
func TestDefenderEmptyIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne}}
	s := runDefender(t, api)
	for _, svc := range []string{"defender.pricings", "defender.autoProvisioning"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestDefenderBudgetExhaustion proves the shared budget bounds the sweep.
func TestDefenderBudgetExhaustion(t *testing.T) {
	c := newDefenderCollector("tenant-1", defenderStub())
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "defender.pricings"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("defender.pricings = %+v, want partial budget-exhausted", got)
	}
}

// TestDefenderEvidenceRedactsToken proves the evidence body is scrubbed.
func TestDefenderEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"pricings":        `{"value":[{"id":"` + vmPlanID + `","name":"` + token + `"}]}`,
	}}
	s := runDefender(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
