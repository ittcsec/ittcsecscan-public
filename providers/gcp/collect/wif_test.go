package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	wifPoolsPage = `{"workloadIdentityPools":[
		{"name":"projects/123/locations/global/workloadIdentityPools/ci-pool","displayName":"CI Pool","state":"ACTIVE","disabled":false}]}`
	// One OIDC provider with NO attribute condition (permissive) and one AWS provider
	// with a condition (scoped).
	wifProvidersPage = `{"workloadIdentityPoolProviders":[
		{"name":"projects/123/locations/global/workloadIdentityPools/ci-pool/providers/gh","displayName":"GitHub","state":"ACTIVE","oidc":{"issuerUri":"https://token.actions.githubusercontent.com","allowedAudiences":["sts"]}},
		{"name":"projects/123/locations/global/workloadIdentityPools/ci-pool/providers/aws","displayName":"AWS","state":"ACTIVE","attributeCondition":"assertion.arn.startsWith('arn:aws:sts::111:')","aws":{"accountId":"111122223333"}}]}`
)

func runWIF(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newWorkloadIdentityCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func gatewayNodeGCP(s collect.Scan, nameSuffix string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeGateway && len(n.NativeID) >= len(nameSuffix) && n.NativeID[len(n.NativeID)-len(nameSuffix):] == nameSuffix {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestWIFMapsPoolsAndProviders proves pools become workload nodes and providers
// become gateway nodes with their external-trust facts: provider type, external
// issuer, and whether an attribute condition narrows the trust (a provider with no
// condition is recorded has_attribute_condition=false, the permissive case).
func TestWIFMapsPoolsAndProviders(t *testing.T) {
	s := runWIF(t, "123", &stubGCP{bodies: map[string]string{
		"workloadIdentityPools?": wifPoolsPage,
		"/providers?":            wifProvidersPage,
	}})

	if c := completenessOf(s, "iam.workloadIdentityPools"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("iam.workloadIdentityPools = %+v, want complete/1", c)
	}
	if c := completenessOf(s, "iam.workloadIdentityPoolProviders"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("iam.workloadIdentityPoolProviders = %+v, want complete/2", c)
	}

	// Pool node.
	var pool collect.Node
	for _, n := range s.Nodes {
		if n.Type == model.NodeWorkload && n.Attributes["gcp_type"] == "wif_pool" {
			pool = n
		}
	}
	if pool.NativeID == "" {
		t.Fatal("no wif_pool node emitted")
	}

	gh, ok := gatewayNodeGCP(s, "/providers/gh")
	if !ok {
		t.Fatal("github provider node not emitted")
	}
	if gh.Attributes["provider_type"] != "oidc" || gh.Attributes["has_attribute_condition"] != "false" ||
		gh.Attributes["external_issuer"] != "https://token.actions.githubusercontent.com" {
		t.Errorf("github provider facts = %+v, want oidc/no-condition/github-issuer", gh.Attributes)
	}

	aws, ok := gatewayNodeGCP(s, "/providers/aws")
	if !ok {
		t.Fatal("aws provider node not emitted")
	}
	if aws.Attributes["provider_type"] != "aws" || aws.Attributes["has_attribute_condition"] != "true" ||
		aws.Attributes["external_issuer"] != "111122223333" {
		t.Errorf("aws provider facts = %+v, want aws/with-condition/account-id", aws.Attributes)
	}

	// The pool contains each provider.
	edges := 0
	for _, l := range s.Links {
		if l.Kind == model.EdgeContains && l.SourceNativeID == pool.NativeID {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("contains edges = %d, want 2", edges)
	}
}

// TestWIFDeniedPoolsIsGap proves a denied pools list is Denied with no nodes, and
// the providers pass is an honest Complete/0.
func TestWIFDeniedPoolsIsGap(t *testing.T) {
	s := runWIF(t, "123", &stubGCP{failSub: "workloadIdentityPools?", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}})
	if statusOf(s, "iam.workloadIdentityPools") != collect.Denied {
		t.Errorf("iam.workloadIdentityPools = %s, want denied", statusOf(s, "iam.workloadIdentityPools"))
	}
	if c := completenessOf(s, "iam.workloadIdentityPoolProviders"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("iam.workloadIdentityPoolProviders = %+v, want complete/0", c)
	}
	if nodesByType(s)[model.NodeGateway] != 0 {
		t.Error("no provider nodes should be emitted on a denied pools list")
	}
}

// TestWIFServiceDisabledIsUnsupported proves a project with the IAM credentials API
// disabled is Unsupported, not Denied.
func TestWIFServiceDisabledIsUnsupported(t *testing.T) {
	s := runWIF(t, "123", &stubGCP{failSub: "workloadIdentityPools?", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "IAM API is not enabled"}})
	if statusOf(s, "iam.workloadIdentityPools") != collect.Unsupported {
		t.Errorf("iam.workloadIdentityPools = %s, want unsupported", statusOf(s, "iam.workloadIdentityPools"))
	}
}

// TestWIFNoProject proves a credential with no default project is Unsupported, never
// an empty-complete.
func TestWIFNoProject(t *testing.T) {
	s := runWIF(t, "", &stubGCP{})
	if statusOf(s, "iam.workloadIdentityPools") != collect.Unsupported {
		t.Errorf("iam.workloadIdentityPools = %s, want unsupported", statusOf(s, "iam.workloadIdentityPools"))
	}
}
