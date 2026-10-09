package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const netPrefix = "https://www.googleapis.com/compute/v1/projects/proj"

// oneNetwork is a networks.list page: one custom-mode VPC with global routing, an
// MTU, and one active peering.
const oneNetwork = `{"items":[
	{"id":"111","name":"vpc-main","autoCreateSubnetworks":false,"mtu":1460,
	 "routingConfig":{"routingMode":"GLOBAL"},
	 "networkFirewallPolicyEnforcementOrder":"AFTER_CLASSIC_FIREWALL",
	 "subnetworks":["` + netPrefix + `/regions/us-central1/subnetworks/sub-a"],
	 "peerings":[{"name":"peer-1","network":"` + netPrefix + `2/global/networks/vpc-other","state":"ACTIVE","exchangeSubnetRoutes":true,"exportCustomRoutes":false}]}
]}`

// subnetworksAgg is a subnetworks.aggregatedList page: one subnet with flow logs on
// (via logConfig), a secondary range and private Google access, in us-central1; one
// bare subnet in europe-west1 (no flow logs, no private access); and an unreachable
// scope reported in-band.
const subnetworksAgg = `{"items":{
	"regions/us-central1":{"subnetworks":[
		{"id":"201","name":"sub-a","network":"` + netPrefix + `/global/networks/vpc-main",
		 "ipCidrRange":"10.0.0.0/20","region":"` + netPrefix + `/regions/us-central1",
		 "gatewayAddress":"10.0.0.1","privateIpGoogleAccess":true,"stackType":"IPV4_ONLY","purpose":"PRIVATE","state":"READY",
		 "logConfig":{"enable":true},
		 "secondaryIpRanges":[{"rangeName":"pods","ipCidrRange":"10.4.0.0/14"}]}
	]},
	"regions/europe-west1":{"subnetworks":[
		{"id":"202","name":"sub-b","network":"` + netPrefix + `/global/networks/vpc-main",
		 "ipCidrRange":"10.8.0.0/20","region":"` + netPrefix + `/regions/europe-west1","state":"READY"}
	]},
	"regions/asia-south2":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}
},"unreachables":["regions/asia-south2"]}`

// twoFirewalls is a firewalls.list page: one INGRESS allow rule from the internet on
// tcp:22,3389 targeting a tag, and one EGRESS deny-all rule.
const twoFirewalls = `{"items":[
	{"id":"301","name":"allow-ssh-rdp","network":"` + netPrefix + `/global/networks/vpc-main","direction":"INGRESS","priority":1000,
	 "sourceRanges":["0.0.0.0/0"],"targetTags":["bastion"],
	 "allowed":[{"IPProtocol":"tcp","ports":["22","3389"]}],
	 "logConfig":{"enable":true}},
	{"id":"302","name":"deny-egress","network":"` + netPrefix + `/global/networks/vpc-main","direction":"EGRESS","priority":65535,"disabled":true,
	 "destinationRanges":["0.0.0.0/0"],
	 "denied":[{"IPProtocol":"all"}]}
]}`

// twoRoutes is a routes.list page: the default internet route and an instance route.
const twoRoutes = `{"items":[
	{"id":"401","name":"default-inet","network":"` + netPrefix + `/global/networks/vpc-main","destRange":"0.0.0.0/0","priority":1000,
	 "nextHopGateway":"` + netPrefix + `/global/gateways/default-internet-gateway","routeType":"STATIC","routeStatus":"ACTIVE"},
	{"id":"402","name":"to-appliance","network":"` + netPrefix + `/global/networks/vpc-main","destRange":"10.10.0.0/16","priority":900,
	 "nextHopIp":"10.0.0.99","tags":["routed"]}
]}`

func fullNetStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"global/networks":        oneNetwork,
		"aggregated/subnetworks": subnetworksAgg,
		"global/firewalls":       twoFirewalls,
		"global/routes":          twoRoutes,
	}}
}

func runNetwork(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newNetworkCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func netNode(s collect.Scan, typ model.NodeType, name string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == typ && n.Name == name {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestNetworkMapsNetwork proves a VPC becomes a network node keyed by its full
// resource name, with configuration and peerings recorded as facts.
func TestNetworkMapsNetwork(t *testing.T) {
	s := runNetwork(t, "proj", fullNetStub())
	n, ok := netNode(s, model.NodeNetwork, "vpc-main")
	if !ok {
		t.Fatal("vpc-main not emitted")
	}
	if n.NativeID != "//compute.googleapis.com/projects/proj/global/networks/vpc-main" {
		t.Errorf("vpc-main keyed by %q", n.NativeID)
	}
	for k, v := range map[string]string{
		"network_id": "111", "auto_create_subnetworks": "false", "routing_mode": "GLOBAL",
		"mtu": "1460", "firewall_enforcement_order": "AFTER_CLASSIC_FIREWALL", "subnetwork_count": "1",
	} {
		if n.Attributes[k] != v {
			t.Errorf("vpc-main %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if p := n.Attributes["peerings"]; !strings.Contains(p, `"name":"peer-1"`) || !strings.Contains(p, `"state":"ACTIVE"`) || !strings.Contains(p, `"exchange_subnet_routes":true`) {
		t.Errorf("peerings fact = %q", p)
	}
}

// TestNetworkMapsSubnetworks proves subnetworks across regions become network nodes
// keyed by region, with flow logs (via logConfig), private Google access, and a
// secondary range as facts, and that an absent security toggle is an explicit fact.
func TestNetworkMapsSubnetworks(t *testing.T) {
	s := runNetwork(t, "proj", fullNetStub())
	a, ok := netNode(s, model.NodeNetwork, "sub-a")
	if !ok {
		t.Fatal("sub-a not emitted")
	}
	if a.NativeID != "//compute.googleapis.com/projects/proj/regions/us-central1/subnetworks/sub-a" {
		t.Errorf("sub-a keyed by %q", a.NativeID)
	}
	for k, v := range map[string]string{
		"network": "vpc-main", "ip_cidr_range": "10.0.0.0/20", "region": "us-central1",
		"private_ip_google_access": "true", "flow_logs": "true", "purpose": "PRIVATE",
	} {
		if a.Attributes[k] != v {
			t.Errorf("sub-a %s = %q, want %q", k, a.Attributes[k], v)
		}
	}
	if sr := a.Attributes["secondary_ranges"]; !strings.Contains(sr, `"range_name":"pods"`) || !strings.Contains(sr, `"ip_cidr_range":"10.4.0.0/14"`) {
		t.Errorf("secondary_ranges = %q", sr)
	}
	// The bare subnet: absent flow logs and private access are explicit false facts.
	b, ok := netNode(s, model.NodeNetwork, "sub-b")
	if !ok {
		t.Fatal("sub-b not emitted")
	}
	for k, v := range map[string]string{"region": "europe-west1", "flow_logs": "false", "private_ip_google_access": "false"} {
		if b.Attributes[k] != v {
			t.Errorf("sub-b %s = %q, want %q (absent toggle must be an explicit fact)", k, b.Attributes[k], v)
		}
	}
	if _, ok := b.Attributes["secondary_ranges"]; ok {
		t.Error("sub-b should have no secondary_ranges attribute")
	}
}

// TestNetworkMapsFirewalls proves firewall rules become control nodes with allow and
// deny protocol lists as canonical-JSON facts, an empty list recorded as "[]", and
// the disabled toggle recorded explicitly.
func TestNetworkMapsFirewalls(t *testing.T) {
	s := runNetwork(t, "proj", fullNetStub())
	allow, ok := netNode(s, model.NodeControl, "allow-ssh-rdp")
	if !ok {
		t.Fatal("allow-ssh-rdp not emitted as a control node")
	}
	for k, v := range map[string]string{
		"network": "vpc-main", "direction": "INGRESS", "priority": "1000", "disabled": "false",
		"source_ranges": "0.0.0.0/0", "target_tags": "bastion", "log_config_enabled": "true",
	} {
		if allow.Attributes[k] != v {
			t.Errorf("allow %s = %q, want %q", k, allow.Attributes[k], v)
		}
	}
	if r := allow.Attributes["allowed_rules"]; !strings.Contains(r, `"protocol":"tcp"`) || !strings.Contains(r, `"22"`) || !strings.Contains(r, `"3389"`) {
		t.Errorf("allowed_rules = %q", r)
	}
	if allow.Attributes["denied_rules"] != "[]" {
		t.Errorf("denied_rules = %q, want [] (no rules is a fact)", allow.Attributes["denied_rules"])
	}
	deny, _ := netNode(s, model.NodeControl, "deny-egress")
	if deny.Attributes["direction"] != "EGRESS" || deny.Attributes["disabled"] != "true" {
		t.Errorf("deny direction/disabled = %q/%q", deny.Attributes["direction"], deny.Attributes["disabled"])
	}
	if deny.Attributes["allowed_rules"] != "[]" || !strings.Contains(deny.Attributes["denied_rules"], `"protocol":"all"`) {
		t.Errorf("deny rules allowed=%q denied=%q", deny.Attributes["allowed_rules"], deny.Attributes["denied_rules"])
	}
}

// TestNetworkMapsRoutes proves routes become network nodes with the next hop
// recorded as a type plus target, URL-valued hops reduced to their last segment and
// the bare IP hop kept as is (the default-internet-gateway hop is the reachability
// signal).
func TestNetworkMapsRoutes(t *testing.T) {
	s := runNetwork(t, "proj", fullNetStub())
	def, ok := netNode(s, model.NodeNetwork, "default-inet")
	if !ok {
		t.Fatal("default-inet route not emitted")
	}
	for k, v := range map[string]string{
		"dest_range": "0.0.0.0/0", "next_hop_type": "gateway", "next_hop": "default-internet-gateway",
		"route_type": "STATIC", "route_status": "ACTIVE", "network": "vpc-main",
	} {
		if def.Attributes[k] != v {
			t.Errorf("default-inet %s = %q, want %q", k, def.Attributes[k], v)
		}
	}
	appl, _ := netNode(s, model.NodeNetwork, "to-appliance")
	if appl.Attributes["next_hop_type"] != "ip" || appl.Attributes["next_hop"] != "10.0.0.99" {
		t.Errorf("to-appliance next hop = %q/%q, want ip/10.0.0.99", appl.Attributes["next_hop_type"], appl.Attributes["next_hop"])
	}
	if appl.Attributes["tags"] != "routed" {
		t.Errorf("to-appliance tags = %q", appl.Attributes["tags"])
	}
}

// TestNetworkAllComplete proves a full sweep records four Complete records except
// subnetworks, which is Partial because a scope was unreachable.
func TestNetworkAllComplete(t *testing.T) {
	s := runNetwork(t, "proj", fullNetStub())
	if c := completenessOf(s, "compute.networks"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("compute.networks = %+v, want complete/1", c)
	}
	if c := completenessOf(s, "compute.firewalls"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("compute.firewalls = %+v, want complete/2", c)
	}
	if c := completenessOf(s, "compute.routes"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("compute.routes = %+v, want complete/2", c)
	}
	c := completenessOf(s, "compute.subnetworks")
	if c.Status != collect.Partial || c.Collected != 2 {
		t.Fatalf("compute.subnetworks = %+v, want partial/2", c)
	}
	if c.Reason != "unreachable: regions/asia-south2" {
		t.Errorf("subnetworks reason = %q", c.Reason)
	}
}

// TestNetworkPaginates proves nextPageToken is followed for a global list (routes).
func TestNetworkPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"global/networks":        `{"items":[]}`,
		"aggregated/subnetworks": `{"items":{}}`,
		"global/firewalls":       `{"items":[]}`,
		"global/routes":          `{"items":[{"name":"r1","network":"n","destRange":"0.0.0.0/0"}],"nextPageToken":"rp2"}`,
		"rp2":                    `{"items":[{"name":"r2","network":"n","destRange":"10.0.0.0/8"}]}`,
	}}
	s := runNetwork(t, "proj", api)
	if c := completenessOf(s, "compute.routes"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("compute.routes = %+v, want complete/2 across pages", c)
	}
}

// TestNetworkDeniedIsGap proves a denied read on one resource is a Denied gap that
// does not fail the run, and the other resources are still collected.
func TestNetworkDeniedIsGap(t *testing.T) {
	api := fullNetStub()
	api.failSub = "global/firewalls"
	api.failWith = &gcpError{status: 403, body: "PERMISSION_DENIED"}
	var s collect.Scan
	if err := newNetworkCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied resource must not fail the run: %v", err)
	}
	if statusOf(s, "compute.firewalls") != collect.Denied {
		t.Errorf("compute.firewalls = %s, want denied", statusOf(s, "compute.firewalls"))
	}
	if statusOf(s, "compute.networks") != collect.Complete || statusOf(s, "compute.routes") != collect.Complete {
		t.Error("other resources should still collect when one is denied")
	}
}

// TestNetworkServiceDisabledIsUnsupported proves a disabled Compute API is
// Unsupported, not Denied.
func TestNetworkServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "global/networks", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Compute Engine API is not enabled"}}
	var s collect.Scan
	if err := newNetworkCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("service-disabled must not fail the run: %v", err)
	}
	if statusOf(s, "compute.networks") != collect.Unsupported {
		t.Errorf("compute.networks = %s, want unsupported", statusOf(s, "compute.networks"))
	}
}

// TestNetworkBudgetExhaustion proves the shared budget bounds the sweep: with budget
// for only the first two resources, the rest are Partial "budget exhausted" and no
// further calls are made.
func TestNetworkBudgetExhaustion(t *testing.T) {
	api := fullNetStub()
	c := newNetworkCollector("proj", api)
	c.budget = collect.NewBudget(2) // networks + subnetworks only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 2 {
		t.Errorf("made %d calls under a 2-call budget; want 2", api.calls)
	}
	for _, svc := range []string{"compute.firewalls", "compute.routes"} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestNetworkEmptyProjectIsUnsupported proves that with no project, every resource is
// a represented Unsupported gap and no call is made.
func TestNetworkEmptyProjectIsUnsupported(t *testing.T) {
	api := &stubGCP{}
	s := runNetwork(t, "", api)
	for _, svc := range []string{"compute.networks", "compute.subnetworks", "compute.firewalls", "compute.routes"} {
		if statusOf(s, svc) != collect.Unsupported {
			t.Errorf("%s = %s, want unsupported", svc, statusOf(s, svc))
		}
	}
	if api.calls != 0 {
		t.Errorf("made %d calls with no project; want 0", api.calls)
	}
}

// TestNetworkEvidenceRedactsToken proves the evidence body is scrubbed.
func TestNetworkEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("Z", 40)
	api := &stubGCP{bodies: map[string]string{
		"global/networks":        `{"items":[{"name":"` + token + `"}]}`,
		"aggregated/subnetworks": `{"items":{}}`,
		"global/firewalls":       `{"items":[]}`,
		"global/routes":          `{"items":[]}`,
	}}
	s := runNetwork(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
