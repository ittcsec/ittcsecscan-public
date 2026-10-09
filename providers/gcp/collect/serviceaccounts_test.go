package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubGCP is an offline gcpAPI. It matches a request URL to a canned body by the
// longest matching substring (most specific wins), so a test drives pagination
// and per-page behaviour deterministically with no network, no token, and no SDK.
type stubGCP struct {
	bodies   map[string]string // url substring -> JSON body
	failSub  string            // return failWith for a URL containing this
	failWith error
	calls    int
}

func (s *stubGCP) get(_ context.Context, url string) ([]byte, error) {
	s.calls++
	if s.failWith != nil && s.failSub != "" && strings.Contains(url, s.failSub) {
		return nil, s.failWith
	}
	// Match the key whose fragment appears latest in the URL. A page-token value
	// appears after the resource name in a later-page URL, so a later page's body
	// wins over the first-page body; the first-page URL matches only the resource
	// key. This avoids a first-page body being returned for a later page (which
	// would loop forever).
	best, bestAt := "", -1
	for sub := range s.bodies {
		if at := strings.LastIndex(url, sub); at > bestAt {
			best, bestAt = sub, at
		}
	}
	if best != "" {
		return []byte(s.bodies[best]), nil
	}
	return []byte(`{}`), nil
}

const twoServiceAccounts = `{"accounts":[
	{"email":"sa1@p.iam.gserviceaccount.com","displayName":"SA One","uniqueId":"111","disabled":false},
	{"email":"sa2@p.iam.gserviceaccount.com","displayName":"SA Two","uniqueId":"222"}]}`

func runCollect(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newIdentityCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodesByType(s collect.Scan) map[model.NodeType]int {
	m := map[model.NodeType]int{}
	for _, n := range s.Nodes {
		m[n.Type]++
	}
	return m
}

func statusOf(s collect.Scan, service string) collect.Status {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c.Status
		}
	}
	return ""
}

// TestCollectMapsServiceAccounts proves the project's service accounts become the
// project node plus workload (machine identity) nodes, with the enumeration
// Complete and scoped to the project.
func TestCollectMapsServiceAccounts(t *testing.T) {
	s := runCollect(t, "scanner-project", &stubGCP{bodies: map[string]string{"serviceAccounts": twoServiceAccounts}})

	byType := nodesByType(s)
	if byType[model.NodeProject] != 1 {
		t.Errorf("project nodes = %d, want 1", byType[model.NodeProject])
	}
	// The approved mapping: a service account is machine identity, a workload.
	if byType[model.NodeWorkload] != 2 {
		t.Errorf("workload (service account) nodes = %d, want 2", byType[model.NodeWorkload])
	}
	if byType[model.NodeIdentity] != 0 {
		t.Errorf("service accounts must not be human identity nodes; got %d", byType[model.NodeIdentity])
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Complete {
		t.Errorf("status = %s, want complete", statusOf(s, "iam.serviceAccounts"))
	}
	for _, c := range s.Completeness {
		if c.Scope.Account != "scanner-project" {
			t.Errorf("scope account = %q, want scanner-project", c.Scope.Account)
		}
	}
	if len(s.Envelopes) != 1 {
		t.Errorf("evidence envelopes = %d, want 1", len(s.Envelopes))
	}
}

// TestCollectPaginates proves nextPageToken is followed to completion.
func TestCollectPaginates(t *testing.T) {
	s := runCollect(t, "scanner-project", &stubGCP{bodies: map[string]string{
		"serviceAccounts": `{"accounts":[{"email":"sa1@p.iam.gserviceaccount.com","uniqueId":"1"}],"nextPageToken":"pgtwo"}`,
		"pgtwo":           `{"accounts":[{"email":"sa2@p.iam.gserviceaccount.com","uniqueId":"2"}]}`,
	}})
	if got := nodesByType(s)[model.NodeWorkload]; got != 2 {
		t.Errorf("workload nodes across pages = %d, want 2", got)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Complete {
		t.Errorf("paginated status = %s, want complete", statusOf(s, "iam.serviceAccounts"))
	}
}

// TestCollectPageLimitStopsRunawayPagination proves the collector bounds
// pagination: an endpoint that returns a next-page token forever is stopped at
// the page limit and recorded as Partial, never followed into a hang.
func TestCollectPageLimitStopsRunawayPagination(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"serviceAccounts": `{"accounts":[{"email":"sa@p.iam.gserviceaccount.com"}],"nextPageToken":"spin"}`,
		"spin":            `{"accounts":[{"email":"sa@p.iam.gserviceaccount.com"}],"nextPageToken":"spin"}`,
	}}
	var s collect.Scan
	if err := newIdentityCollector("scanner-project", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Partial {
		t.Errorf("status = %s, want partial (page limit reached)", statusOf(s, "iam.serviceAccounts"))
	}
	if api.calls > maxPages+1 {
		t.Errorf("made %d API calls; must stop at the page limit (%d)", api.calls, maxPages)
	}
}

// TestCollectBudgetExhaustionMidPagination proves the shared call budget bites:
// with budget for one page, the first page is collected and the next is a
// recorded Partial "budget exhausted" gap, its call never made.
func TestCollectBudgetExhaustionMidPagination(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"serviceAccounts": `{"accounts":[{"email":"sa1@p.iam.gserviceaccount.com"}],"nextPageToken":"pgtwo"}`,
		"pgtwo":           `{"accounts":[{"email":"sa2@p.iam.gserviceaccount.com"}]}`,
	}}
	c := newIdentityCollector("scanner-project", api)
	c.budget = collect.NewBudget(1)

	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 1 {
		t.Errorf("made %d calls under a 1-call budget; want 1", api.calls)
	}
	if nodesByType(s)[model.NodeWorkload] != 1 {
		t.Errorf("collected %d service accounts; want 1 (the first page only)", nodesByType(s)[model.NodeWorkload])
	}
	c0 := s.Completeness[0]
	if c0.Status != collect.Partial || c0.Reason != "budget exhausted" {
		t.Fatalf("status = %+v, want partial with reason budget exhausted", c0)
	}
}

// TestCollectEmptyProjectIsUnsupported proves that with no project to scope to,
// the enumeration is a represented Unsupported gap, not an error and not a call.
func TestCollectEmptyProjectIsUnsupported(t *testing.T) {
	api := &stubGCP{}
	var s collect.Scan
	if err := newIdentityCollector("", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("made %d API calls with no project; want 0", api.calls)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "iam.serviceAccounts"))
	}
	if len(s.Nodes) != 0 {
		t.Errorf("emitted %d nodes with no project; want 0", len(s.Nodes))
	}
}

// TestErrorReasonAndServiceDisabled proves an API-not-enabled 403
// (SERVICE_DISABLED) is told apart from a real access denial. The bodies are the
// shapes GCP actually returns (the SERVICE_DISABLED one captured from a live scan
// against a project with the IAM API disabled).
func TestErrorReasonAndServiceDisabled(t *testing.T) {
	disabled := []byte(`{"error":{"code":403,"message":"Identity and Access Management (IAM) API has not been used in project 673777805718 before or it is disabled.","status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED","domain":"googleapis.com"}]}}`)
	if got := errorReason(disabled); got != "SERVICE_DISABLED" {
		t.Errorf("errorReason = %q, want SERVICE_DISABLED", got)
	}
	denied := []byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"IAM_PERMISSION_DENIED"}]}}`)
	if got := errorReason(denied); got != "IAM_PERMISSION_DENIED" {
		t.Errorf("errorReason = %q, want IAM_PERMISSION_DENIED", got)
	}

	// SERVICE_DISABLED classifies as unsupported (enable the API), not denied.
	sd := &gcpError{status: 403, reason: "SERVICE_DISABLED"}
	if !isServiceDisabled(sd) || isDenied(sd) {
		t.Error("SERVICE_DISABLED must be unsupported, not denied")
	}
	// A real permission denial is denied, not service-disabled.
	pd := &gcpError{status: 403, reason: "IAM_PERMISSION_DENIED"}
	if isServiceDisabled(pd) || !isDenied(pd) {
		t.Error("IAM_PERMISSION_DENIED must be denied, not service-disabled")
	}
}

// TestCollectServiceDisabledIsUnsupported proves a disabled-API 403 is a recorded
// Unsupported gap (the remediation is to enable the API), not a Denied one, and
// not a run error.
func TestCollectServiceDisabledIsUnsupported(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("scanner-project", &stubGCP{
		failSub:  "serviceAccounts",
		failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "IAM API is not enabled"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("service-disabled must not surface as a run error: %v", err)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "iam.serviceAccounts"))
	}
}

// TestCollectDeniedIsGapNotError proves a 403 is a recorded Denied gap, not a run
// error.
func TestCollectDeniedIsGapNotError(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("scanner-project", &stubGCP{
		failSub: "serviceAccounts", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("denied read must not surface as a run error: %v", err)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "iam.serviceAccounts"))
	}
}

// TestCollectThrottleIsPartial proves a 429 is a represented Partial gap, not an
// error.
func TestCollectThrottleIsPartial(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("scanner-project", &stubGCP{
		failSub: "serviceAccounts", failWith: &gcpError{status: 429, body: "RESOURCE_EXHAUSTED"},
	}).Collect(context.Background(), &s)
	if err != nil {
		t.Fatalf("throttle must not surface as a run error: %v", err)
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Partial {
		t.Errorf("status = %s, want partial", statusOf(s, "iam.serviceAccounts"))
	}
}

// TestCollectUnexpectedErrorSurfaces proves an unexpected failure (500) is
// recorded as Errored and surfaced, never swallowed into a pass.
func TestCollectUnexpectedErrorSurfaces(t *testing.T) {
	var s collect.Scan
	err := newIdentityCollector("scanner-project", &stubGCP{
		failSub: "serviceAccounts", failWith: &gcpError{status: 500, body: "INTERNAL"},
	}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if statusOf(s, "iam.serviceAccounts") != collect.Errored {
		t.Errorf("status = %s, want error", statusOf(s, "iam.serviceAccounts"))
	}
}

// TestEvidenceRedactsToken proves the evidence body is scrubbed.
func TestEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("Z", 60)
	body := `{"accounts":[{"email":"sa@p.iam.gserviceaccount.com","displayName":"` + token + `"}]}`
	s := runCollect(t, "scanner-project", &stubGCP{bodies: map[string]string{"serviceAccounts": body}})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
