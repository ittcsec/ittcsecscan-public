package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// zonePrefix is a full compute resource URL prefix; the collector reduces these to
// their last segment (zone, machineType, network, subnetwork).
const zonePrefix = "https://www.googleapis.com/compute/v1/projects/proj"

// twoInstances is an aggregatedList page: one full-featured RUNNING instance in
// us-central1-a with an external IP, network tags, a label, Shielded VM config, and
// an attached service account (the run-as edge), and one "bare" TERMINATED instance
// in europe-west1-b with no external IP and no service account.
const twoInstances = `{"items":{
	"zones/us-central1-a":{"instances":[
		{"id":"7788","name":"web-1",
		 "zone":"` + zonePrefix + `/zones/us-central1-a",
		 "machineType":"` + zonePrefix + `/zones/us-central1-a/machineTypes/e2-medium",
		 "status":"RUNNING",
		 "labels":{"env":"prod"},
		 "tags":{"items":["http-server","https-server"]},
		 "serviceAccounts":[{"email":"runtime@proj.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/cloud-platform"]}],
		 "networkInterfaces":[{"network":"` + zonePrefix + `/global/networks/default","subnetwork":"` + zonePrefix + `/regions/us-central1/subnetworks/sub-a","networkIP":"10.0.0.5","accessConfigs":[{"natIP":"34.1.2.3"}]}],
		 "shieldedInstanceConfig":{"enableSecureBoot":true,"enableVtpm":true,"enableIntegrityMonitoring":false}}
	]},
	"zones/europe-west1-b":{"instances":[
		{"id":"9900","name":"batch-1",
		 "zone":"` + zonePrefix + `/zones/europe-west1-b",
		 "machineType":"` + zonePrefix + `/zones/europe-west1-b/machineTypes/n1-standard-1",
		 "status":"TERMINATED",
		 "networkInterfaces":[{"network":"` + zonePrefix + `/global/networks/default","subnetwork":"` + zonePrefix + `/regions/europe-west1/subnetworks/sub-b","networkIP":"10.1.0.7","accessConfigs":[]}]}
	]},
	"zones/us-west1-a":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}
}}`

func runInstances(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newInstanceCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func instanceNode(s collect.Scan, name string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeCompute && n.Name == name {
			return n, true
		}
	}
	return collect.Node{}, false
}

func instancesStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{"returnPartialSuccess": twoInstances}}
}

// TestInstancesMapsInstances proves instances across zones become compute nodes
// keyed by their full resource name, with configuration recorded as facts (machine
// type, status, zone, network tags, labels, network, internal and external IP, and
// Shielded VM config, each reduced from its full URL where GCP returns one).
func TestInstancesMapsInstances(t *testing.T) {
	s := runInstances(t, "proj", instancesStub())

	if n := nodesByType(s)[model.NodeCompute]; n != 2 {
		t.Fatalf("compute nodes = %d, want 2", n)
	}
	web, ok := instanceNode(s, "web-1")
	if !ok {
		t.Fatal("web-1 not emitted")
	}
	if web.NativeID != "//compute.googleapis.com/projects/proj/zones/us-central1-a/instances/web-1" {
		t.Errorf("web-1 keyed by %q, want its full resource name", web.NativeID)
	}
	for k, v := range map[string]string{
		"instance_id":                   "7788",
		"machine_type":                  "e2-medium",
		"status":                        "RUNNING",
		"zone":                          "us-central1-a",
		"network_tags":                  "http-server,https-server",
		"label:env":                     "prod",
		"network":                       "default",
		"subnetwork":                    "sub-a",
		"internal_ip":                   "10.0.0.5",
		"public_ip":                     "34.1.2.3",
		"shielded_secure_boot":          "true",
		"shielded_vtpm":                 "true",
		"shielded_integrity_monitoring": "false",
		"service_account_email":         "runtime@proj.iam.gserviceaccount.com",
		"service_account_scopes":        "https://www.googleapis.com/auth/cloud-platform",
	} {
		if web.Attributes[k] != v {
			t.Errorf("web-1 %s = %q, want %q", k, web.Attributes[k], v)
		}
	}
}

// TestInstancesBareInstanceOmitsAbsentFacts proves a bare instance (no external IP,
// no service account, no Shielded config) carries no public_ip, no run-as edge, and
// no Shielded attributes: an absent optional field is simply not asserted.
func TestInstancesBareInstanceOmitsAbsentFacts(t *testing.T) {
	s := runInstances(t, "proj", instancesStub())
	bare, ok := instanceNode(s, "batch-1")
	if !ok {
		t.Fatal("batch-1 not emitted")
	}
	if bare.Attributes["status"] != "TERMINATED" || bare.Attributes["zone"] != "europe-west1-b" {
		t.Errorf("batch-1 status/zone = %q/%q", bare.Attributes["status"], bare.Attributes["zone"])
	}
	for _, k := range []string{"public_ip", "service_account_email", "shielded_secure_boot"} {
		if _, ok := bare.Attributes[k]; ok {
			t.Errorf("batch-1 should not assert %s", k)
		}
	}
}

// TestInstancesRunAsEdge proves the instance-to-service-account run-as edge is
// emitted, keyed by the service account's bare email so it merges with the
// service-account and IAM-policy collectors' nodes, and that a bare instance
// produces no such edge.
func TestInstancesRunAsEdge(t *testing.T) {
	s := runInstances(t, "proj", instancesStub())

	const saEmail = "runtime@proj.iam.gserviceaccount.com"
	web, _ := instanceNode(s, "web-1")
	var edges int
	for _, l := range s.Links {
		if l.Kind != model.EdgeAssumes {
			t.Errorf("edge kind = %s, want assumes", l.Kind)
		}
		if l.SourceNativeID == web.NativeID && l.TargetNativeID == saEmail {
			edges++
		}
	}
	if edges != 1 {
		t.Fatalf("web-1 run-as edges to %s = %d, want 1", saEmail, edges)
	}
	// The service account is a workload node keyed by its bare email.
	var sawSA bool
	for _, n := range s.Nodes {
		if n.Type == model.NodeWorkload && n.NativeID == saEmail {
			sawSA = true
		}
	}
	if !sawSA {
		t.Error("run-as target service account not emitted as a workload node keyed by its bare email")
	}
	if len(s.Links) != 1 {
		t.Errorf("total run-as edges = %d, want 1 (batch-1 has no service account)", len(s.Links))
	}
}

// TestInstancesUnreachableIsPartial proves an unreachable scope reported in the
// response's unreachables field makes the single compute.instances record Partial,
// naming the scopes, while the instances that were reached are still emitted.
func TestInstancesUnreachableIsPartial(t *testing.T) {
	body := `{"items":{"zones/us-central1-a":{"instances":[{"name":"web-1","zone":"zones/us-central1-a"}]}},
		"unreachables":["zones/asia-south2-a","zones/asia-south2-b"]}`
	s := runInstances(t, "proj", &stubGCP{bodies: map[string]string{"returnPartialSuccess": body}})

	if n := nodesByType(s)[model.NodeCompute]; n != 1 {
		t.Errorf("compute nodes = %d, want 1 (reached zones still mapped)", n)
	}
	c := completenessOf(s, "compute.instances")
	if c.Status != collect.Partial {
		t.Fatalf("compute.instances = %s, want partial", c.Status)
	}
	if c.Reason != "unreachable: zones/asia-south2-a,zones/asia-south2-b" {
		t.Errorf("reason = %q, want the unreachable scopes named and sorted", c.Reason)
	}
}

// TestInstancesPaginates proves nextPageToken is followed across pages and the
// aggregate completeness counts every instance.
func TestInstancesPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"returnPartialSuccess": `{"items":{"zones/z1":{"instances":[{"name":"i1","zone":"zones/z1"}]}},"nextPageToken":"pg2"}`,
		"pg2":                  `{"items":{"zones/z2":{"instances":[{"name":"i2","zone":"zones/z2"}]}}}`,
	}}
	s := runInstances(t, "proj", api)
	if n := nodesByType(s)[model.NodeCompute]; n != 2 {
		t.Errorf("instances across pages = %d, want 2", n)
	}
	if c := completenessOf(s, "compute.instances"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("compute.instances = %+v, want complete with 2", c)
	}
}

// TestInstancesNoInstancesIsComplete proves an empty project is an honest Complete/0,
// not a gap.
func TestInstancesNoInstancesIsComplete(t *testing.T) {
	s := runInstances(t, "proj", &stubGCP{bodies: map[string]string{"returnPartialSuccess": `{"items":{}}`}})
	if c := completenessOf(s, "compute.instances"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("compute.instances = %+v, want complete with 0", c)
	}
	if n := nodesByType(s)[model.NodeCompute]; n != 0 {
		t.Errorf("compute nodes = %d, want 0", n)
	}
}

// TestInstancesDeniedIsGap proves a denied aggregatedList is a recorded Denied gap
// with no nodes, not a run error.
func TestInstancesDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "returnPartialSuccess", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newInstanceCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("denied list must not fail the run: %v", err)
	}
	if statusOf(s, "compute.instances") != collect.Denied {
		t.Errorf("compute.instances = %s, want denied", statusOf(s, "compute.instances"))
	}
	if n := nodesByType(s)[model.NodeCompute]; n != 0 {
		t.Errorf("compute nodes = %d, want 0", n)
	}
}

// TestInstancesServiceDisabledIsUnsupported proves a disabled Compute API is
// recorded Unsupported, not Denied.
func TestInstancesServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "returnPartialSuccess", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Compute Engine API is not enabled"}}
	var s collect.Scan
	if err := newInstanceCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("service-disabled must not fail the run: %v", err)
	}
	if statusOf(s, "compute.instances") != collect.Unsupported {
		t.Errorf("compute.instances = %s, want unsupported", statusOf(s, "compute.instances"))
	}
}

// TestInstancesThrottleIsPartial proves a throttled read is a non-fatal Partial gap.
func TestInstancesThrottleIsPartial(t *testing.T) {
	api := &stubGCP{failSub: "returnPartialSuccess", failWith: &gcpError{status: 429, body: "RESOURCE_EXHAUSTED"}}
	var s collect.Scan
	if err := newInstanceCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("throttle must not fail the run: %v", err)
	}
	if statusOf(s, "compute.instances") != collect.Partial {
		t.Errorf("compute.instances = %s, want partial", statusOf(s, "compute.instances"))
	}
}

// TestInstancesEmptyProjectIsUnsupported proves that with no project to scope to,
// the enumeration is a represented Unsupported gap, not an error and not a call.
func TestInstancesEmptyProjectIsUnsupported(t *testing.T) {
	api := &stubGCP{}
	if s := runInstances(t, "", api); statusOf(s, "compute.instances") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "compute.instances"))
	}
	if api.calls != 0 {
		t.Errorf("made %d calls with no project; want 0", api.calls)
	}
}

// TestInstancesBudgetExhaustion proves the shared budget bounds the enumeration: a
// zero budget makes no call and records a Partial "budget exhausted" gap.
func TestInstancesBudgetExhaustion(t *testing.T) {
	api := instancesStub()
	c := newInstanceCollector("proj", api)
	c.budget = collect.NewBudget(0)
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("made %d calls under a 0-call budget; want 0", api.calls)
	}
	if got := completenessOf(s, "compute.instances"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("compute.instances = %+v, want partial budget-exhausted", got)
	}
}

// TestInstancesEvidenceRedactsToken proves the evidence body is scrubbed.
func TestInstancesEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("Z", 40)
	api := &stubGCP{bodies: map[string]string{
		"returnPartialSuccess": `{"items":{"zones/z1":{"instances":[{"name":"` + token + `","zone":"zones/z1"}]}}}`,
	}}
	s := runInstances(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}

func TestLastSegment(t *testing.T) {
	for in, want := range map[string]string{
		zonePrefix + "/zones/us-central1-a": "us-central1-a",
		"e2-medium":                         "e2-medium",
		"":                                  "",
	} {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}
