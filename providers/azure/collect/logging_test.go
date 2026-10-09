package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	workspaceID = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/law1"
	diagID      = "/subscriptions/sub-1/providers/Microsoft.Insights/diagnosticSettings/activity-to-law"
)

// oneWorkspace is a workspaces list page: one workspace with 90-day retention, local
// auth disabled, and public query access disabled.
const oneWorkspace = `{"value":[
	{"id":"` + workspaceID + `","name":"law1","location":"eastus","tags":{"env":"prod"},
	 "properties":{
	   "customerId":"cust-guid","provisioningState":"Succeeded",
	   "sku":{"name":"PerGB2018"},"retentionInDays":90,
	   "publicNetworkAccessForIngestion":"Enabled","publicNetworkAccessForQuery":"Disabled",
	   "features":{"disableLocalAuth":true,"immediatePurgeDataOn30Days":false},
	   "workspaceCapping":{"dailyQuotaGb":5}}}
]}`

// oneDiagnosticSetting is a subscription diagnostic-settings list page (no nextLink):
// the Activity Log exported to a Log Analytics workspace with two categories, given
// out of order to prove sorting.
const oneDiagnosticSetting = `{"value":[
	{"id":"` + diagID + `","name":"activity-to-law",
	 "properties":{
	   "workspaceId":"` + workspaceID + `",
	   "storageAccountId":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/auditsa",
	   "logs":[
	     {"category":"Security","enabled":true},
	     {"category":"Administrative","enabled":true},
	     {"categoryGroup":"audit","enabled":false}
	   ]}}
]}`

func loggingStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?":     subsOne,
		"OperationalInsights": oneWorkspace,
		"diagnosticSettings":  oneDiagnosticSetting,
	}}
}

func runLogging(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newLoggingCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestLoggingWorkspace proves a Log Analytics workspace becomes a control node keyed
// by its ARM resource id with its retention and access posture.
func TestLoggingWorkspace(t *testing.T) {
	s := runLogging(t, loggingStub())

	n, ok := nodeNamed(s, model.NodeControl, workspaceID)
	if !ok {
		t.Fatal("law1 not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "log_analytics_workspace", "location": "eastus", "customer_id": "cust-guid",
		"sku": "PerGB2018", "retention_days": "90", "public_network_access_query": "Disabled",
		"disable_local_auth": "true", "immediate_purge_30_days": "false", "daily_quota_gb": "5",
		"tag:env": "prod",
	} {
		if n.Attributes[k] != want {
			t.Errorf("law1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	if c := completenessOf(s, "logging.workspaces"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("logging.workspaces = %+v, want complete/1", c)
	}
}

// TestLoggingDiagnosticSetting proves the subscription Activity Log setting becomes a
// control node with its destination sinks as join keys and its enabled log categories
// as a sorted canonical-JSON fact, with no synthesized sufficiency verdict.
func TestLoggingDiagnosticSetting(t *testing.T) {
	s := runLogging(t, loggingStub())

	n, ok := nodeNamed(s, model.NodeControl, diagID)
	if !ok {
		t.Fatal("diagnostic setting not keyed by its ARM resource id")
	}
	if n.Attributes["azure_type"] != "diagnostic_setting" || n.Attributes["scope"] != "subscription" {
		t.Errorf("diagnostic setting type/scope = %q/%q", n.Attributes["azure_type"], n.Attributes["scope"])
	}
	// Destination sinks join onto the workspace and storage nodes.
	if n.Attributes["workspace_id"] != workspaceID {
		t.Errorf("workspace_id = %q, want %q", n.Attributes["workspace_id"], workspaceID)
	}
	if !strings.Contains(n.Attributes["storage_account_id"], "auditsa") {
		t.Errorf("storage_account_id not recorded: %q", n.Attributes["storage_account_id"])
	}
	logs := n.Attributes["logs"]
	if i, j := strings.Index(logs, "Administrative"), strings.Index(logs, "Security"); i < 0 || j < 0 || i > j {
		t.Errorf("logs not sorted by category: %s", logs)
	}
	if !strings.Contains(logs, `"category":"Security","enabled":true`) {
		t.Errorf("enabled category not carried: %s", logs)
	}
	for _, forbidden := range []string{"audit_enabled", "compliant", "sufficient"} {
		if _, bad := n.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
}

// TestLoggingDeniedIsGap proves a denied read of one resource is a Denied gap that
// does not fail the run and does not block the other.
func TestLoggingDeniedIsGap(t *testing.T) {
	api := loggingStub()
	api.failSub = "diagnosticSettings"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newLoggingCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "logging.diagnosticSettings") != collect.Denied {
		t.Errorf("logging.diagnosticSettings = %s, want denied", statusOf(s, "logging.diagnosticSettings"))
	}
	if _, ok := nodeNamed(s, model.NodeControl, diagID); ok {
		t.Error("a denied read must not emit a diagnostic-setting node")
	}
	if statusOf(s, "logging.workspaces") != collect.Complete {
		t.Errorf("workspaces should still be complete, got %s", statusOf(s, "logging.workspaces"))
	}
}

// TestLoggingEmptyIsComplete proves an empty subscription is an honest Complete/0 for
// both resources.
func TestLoggingEmptyIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne}}
	s := runLogging(t, api)
	for _, svc := range []string{"logging.workspaces", "logging.diagnosticSettings"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestLoggingWorkspacePaginates proves nextLink is followed across workspace pages.
func TestLoggingWorkspacePaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":     subsOne,
		"OperationalInsights": `{"value":[{"id":"` + workspaceID + `a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":                 `{"value":[{"id":"` + workspaceID + `b","name":"b"}]}`,
	}}
	s := runLogging(t, api)
	n := 0
	for _, node := range s.Nodes {
		if node.Attributes["azure_type"] == "log_analytics_workspace" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("workspaces across pages = %d, want 2", n)
	}
}

// TestLoggingBudgetExhaustion proves the shared budget bounds the sweep.
func TestLoggingBudgetExhaustion(t *testing.T) {
	c := newLoggingCollector("tenant-1", loggingStub())
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "logging.workspaces"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("logging.workspaces = %+v, want partial budget-exhausted", got)
	}
}

// TestLoggingEvidenceRedactsToken proves the evidence body is scrubbed.
func TestLoggingEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":     subsOne,
		"OperationalInsights": `{"value":[{"id":"` + workspaceID + `","name":"` + token + `"}]}`,
	}}
	s := runLogging(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
