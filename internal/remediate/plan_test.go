package remediate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

func awsBucket() model.Entity {
	return model.Entity{
		SchemaVersion: model.SchemaVersion,
		ID:            model.StableID(strings.Repeat("a", 64)),
		Provider:      model.AWS,
		Type:          model.NodeDataStore,
		NativeID:      "arn:aws:s3:::acme-public-bucket",
		Name:          "acme-public-bucket",
		Attributes:    map[string]string{"policy_is_public": "true"},
	}
}

func ref(id string) model.RuleRef { return model.RuleRef{RuleID: id, Version: "1", PackID: "core-p0"} }

// A known rule yields a complete, apply-ready plan: real actions with CLI, portal
// steps, and IaC, plus privilege, verification, a current-state hash, and a plan
// hash. This is the shape that closes RP-1.
func TestPlanForKnownRuleIsComplete(t *testing.T) {
	p := Plan(ref("CORE-P0-STORAGE-PUBLIC-AWS"), awsBucket())
	if !p.Available {
		t.Fatal("expected an available plan for a templated rule")
	}
	if len(p.Actions) == 0 {
		t.Fatal("available plan has no actions")
	}
	a := p.Actions[0]
	if len(a.CLI) == 0 || len(a.PortalSteps) == 0 || a.IaC == "" || len(a.Privilege) == 0 {
		t.Errorf("action is missing a rendering: cli=%d portal=%d iac=%q priv=%d", len(a.CLI), len(a.PortalSteps), a.IaC, len(a.Privilege))
	}
	if !strings.Contains(a.CLI[0], "acme-public-bucket") {
		t.Errorf("CLI not parameterized with the resource: %q", a.CLI[0])
	}
	if len(p.Verification) == 0 || len(p.RequiredPrivilege) == 0 {
		t.Error("plan missing verification or required privilege")
	}
	if p.CurrentStateHash == "" || p.PlanHash == "" {
		t.Error("plan missing a state hash or plan hash")
	}
	if p.Entity != awsBucket().ID {
		t.Error("plan not bound to the finding's entity")
	}
}

// Plan generation is deterministic: identical inputs produce a byte-identical
// plan, including the PlanHash an approval binds to.
func TestPlanIsDeterministic(t *testing.T) {
	a := Plan(ref("CORE-P0-STORAGE-PUBLIC-AWS"), awsBucket())
	b := Plan(ref("CORE-P0-STORAGE-PUBLIC-AWS"), awsBucket())
	if !reflect.DeepEqual(a, b) {
		t.Error("plan generation is not deterministic")
	}
	if a.PlanHash != b.PlanHash {
		t.Errorf("plan hash not stable: %s vs %s", a.PlanHash, b.PlanHash)
	}
}

// The never-fabricate guarantee: the three compute-exposure rules have no
// mechanical fix, so they must be honest named gaps (RP-6), never an action.
// Breaking this (adding a compute template to catalog.go) makes this test fail.
func TestComputeRulesAreHonestGapsNotFabrications(t *testing.T) {
	for _, id := range []string{
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS",
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-AZURE",
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-GCP",
	} {
		p := Plan(ref(id), model.Entity{ID: awsBucket().ID, Provider: model.AWS, Type: model.NodeCompute})
		if p.Available {
			t.Errorf("%s: fabricated an available plan for a rule with no mechanical fix", id)
		}
		if len(p.Actions) != 0 {
			t.Errorf("%s: gap plan carries %d actions; it must carry none", id, len(p.Actions))
		}
		if !strings.Contains(p.GapReason, "RP-6") {
			t.Errorf("%s: gap reason does not name the tracked gap: %q", id, p.GapReason)
		}
		if p.PlanHash == "" {
			t.Errorf("%s: even a gap plan must be hashed", id)
		}
	}
}

// Broader never-fabricate invariant: any rule without a template is a gap with no
// actions. Guards against a future rule id silently getting a blank action list
// that reads as "nothing to do".
func TestUnknownRuleIsHonestGap(t *testing.T) {
	p := Plan(ref("CORE-P0-SOMETHING-NEW"), awsBucket())
	if p.Available || len(p.Actions) != 0 {
		t.Error("unknown rule must be an unavailable gap with no actions")
	}
	if p.GapReason == "" {
		t.Error("gap plan must state a reason")
	}
}

// Key Vault purge protection is irreversible; the plan must say so and must not
// promise a rollback that does not exist.
func TestKeyVaultPurgeIsHonestlyIrreversible(t *testing.T) {
	e := model.Entity{
		ID: awsBucket().ID, Provider: model.Azure, Type: model.NodeControl, Name: "kv-acme",
		NativeID:   "/subscriptions/s/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv-acme",
		Attributes: map[string]string{"purge_protection": "false"},
	}
	p := Plan(ref("CORE-P0-KEYVAULT-PURGE-AZURE"), e)
	if !p.Available {
		t.Fatal("expected a plan for the key vault rule")
	}
	if p.Reversible {
		t.Error("key vault purge protection must be marked irreversible")
	}
	joined := strings.ToLower(strings.Join(p.Rollback, " ") + " " + strings.Join(p.SideEffects, " "))
	if !strings.Contains(joined, "cannot") {
		t.Errorf("irreversible plan must state that it cannot be undone: rollback=%v", p.Rollback)
	}
	// resource group parsed from the ARM id, not invented
	if !strings.Contains(p.Actions[0].CLI[0], "rg-sec") {
		t.Errorf("resource group not parsed from the native id: %q", p.Actions[0].CLI[0])
	}
}

// The Azure database rule spans four engines with different CLIs; the plan must
// select the one matching the entity's engine fact, never guess.
func TestAzureDatabaseSelectsCLIByEngine(t *testing.T) {
	base := "/subscriptions/s/resourceGroups/rg-db/providers/Microsoft.Sql/servers/srv"
	cases := map[string]string{
		"sql":        "az sql server update",
		"postgresql": "az postgres flexible-server update",
		"mysql":      "az mysql flexible-server update",
		"cosmosdb":   "az cosmosdb update",
	}
	for engine, want := range cases {
		e := model.Entity{ID: awsBucket().ID, Provider: model.Azure, Type: model.NodeDataStore, Name: "srv", NativeID: base,
			Attributes: map[string]string{"engine": engine, "public_network_access": "Enabled"}}
		p := Plan(ref("CORE-P0-DATABASE-PUBLIC-AZURE"), e)
		if len(p.Actions) == 0 || !strings.Contains(p.Actions[0].CLI[0], want) {
			t.Errorf("engine %q: CLI %q does not contain %q", engine, cliOrEmpty(p), want)
		}
		if !strings.Contains(p.Actions[0].CLI[0], "rg-db") {
			t.Errorf("engine %q: resource group not parsed into CLI", engine)
		}
	}
}

func cliOrEmpty(p GeneratedPlan) string {
	if len(p.Actions) > 0 && len(p.Actions[0].CLI) > 0 {
		return p.Actions[0].CLI[0]
	}
	return ""
}

// CurrentStateHash underpins drift detection: a config change must change it, an
// identical state must not, and it must not depend on attribute iteration order.
func TestCurrentStateHashTracksState(t *testing.T) {
	e := awsBucket()
	h1 := CurrentStateHash(e)
	if h1 != CurrentStateHash(awsBucket()) {
		t.Error("hash of identical state differs")
	}
	drifted := awsBucket()
	drifted.Attributes["policy_is_public"] = "false"
	if CurrentStateHash(drifted) == h1 {
		t.Error("a changed attribute must change the current-state hash (drift detection depends on this)")
	}
	// order independence: build the same map with keys inserted in a different order
	reordered := awsBucket()
	reordered.Attributes = map[string]string{"z_last": "1", "policy_is_public": "true"}
	e.Attributes = map[string]string{"policy_is_public": "true", "z_last": "1"}
	if CurrentStateHash(reordered) != CurrentStateHash(e) {
		t.Error("current-state hash must be independent of attribute insertion order")
	}
}

// Every authored catalog string is free of em/en dashes (the report honesty gate
// would otherwise rewrite them), so guidance renders as authored.
func TestCatalogHasNoForbiddenDashes(t *testing.T) {
	entities := map[string]model.Entity{
		"CORE-P0-STORAGE-PUBLIC-AWS":             {Provider: model.AWS, Name: "b", NativeID: "arn:aws:s3:::b"},
		"CORE-P0-STORAGE-PUBLIC-AZURE":           {Provider: model.Azure, Name: "sa", NativeID: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"},
		"CORE-P0-STORAGE-PUBLIC-GCP":             {Provider: model.GCP, Name: "bkt", NativeID: "bkt"},
		"CORE-P0-DATABASE-PUBLIC-AWS":            {Provider: model.AWS, Name: "db", NativeID: "db"},
		"CORE-P0-DATABASE-PUBLIC-AZURE":          {Provider: model.Azure, Name: "srv", NativeID: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/srv", Attributes: map[string]string{"engine": "sql"}},
		"CORE-P0-DATABASE-PUBLIC-GCP":            {Provider: model.GCP, Name: "inst", NativeID: "inst"},
		"CORE-P0-KMS-ROTATION-AWS":               {Provider: model.AWS, Name: "key", NativeID: "key"},
		"CORE-P0-KMS-ROTATION-GCP":               {Provider: model.GCP, NativeID: "projects/p/locations/us/keyRings/r/cryptoKeys/k"},
		"CORE-P0-KEYVAULT-PURGE-AZURE":           {Provider: model.Azure, Name: "kv", NativeID: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"},
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS":   {Provider: model.AWS},
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-AZURE": {Provider: model.Azure},
		"CORE-P0-COMPUTE-INTERNET-EXPOSED-GCP":   {Provider: model.GCP},
	}
	for id, e := range entities {
		e.ID = awsBucket().ID
		p := Plan(ref(id), e)
		for _, s := range planStrings(p) {
			if strings.ContainsRune(s, '—') || strings.ContainsRune(s, '–') {
				t.Errorf("%s: authored string contains an em/en dash: %q", id, s)
			}
		}
	}
}

func planStrings(p GeneratedPlan) []string {
	var out []string
	out = append(out, p.GapReason)
	out = append(out, p.Preconditions...)
	out = append(out, p.RequiredPrivilege...)
	out = append(out, p.SideEffects...)
	out = append(out, p.Verification...)
	out = append(out, p.Rollback...)
	for _, a := range p.Actions {
		out = append(out, a.Summary, a.IaC)
		out = append(out, a.PortalSteps...)
		out = append(out, a.CLI...)
		out = append(out, a.Privilege...)
	}
	return out
}
