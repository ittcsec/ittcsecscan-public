package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// routersAgg is a routers.aggregatedList page: one router in us-central1 with a
// public Cloud NAT (auto-allocated IPs, log on) and one unreachable scope.
const routersAgg = `{"items":{
	"regions/us-central1":{"routers":[
		{"id":"501","name":"rtr-a","network":"` + netPrefix + `/global/networks/vpc-main","region":"` + netPrefix + `/regions/us-central1",
		 "bgpPeers":[{}],"interfaces":[{},{}],
		 "nats":[{"name":"nat-a","type":"PUBLIC","natIpAllocateOption":"AUTO_ONLY","sourceSubnetworkIpRangesToNat":"ALL_SUBNETWORKS_ALL_IP_RANGES","logConfig":{"enable":true}}]}
	]},
	"regions/asia-south2":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}
},"unreachables":["regions/asia-south2"]}`

// addressesAgg is an addresses.aggregatedList page: one in-use external regional IP.
const addressesAgg = `{"items":{
	"regions/us-central1":{"addresses":[
		{"id":"601","name":"ext-a","address":"34.10.20.30","addressType":"EXTERNAL","status":"IN_USE","networkTier":"PREMIUM","ipVersion":"IPV4",
		 "region":"` + netPrefix + `/regions/us-central1","users":["` + netPrefix + `/zones/us-central1-a/instances/web-1"]}
	]}
}}`

// globalAddressesList is a globalAddresses.list page: one reserved global internal IP
// for private service access.
const globalAddressesList = `{"items":[
	{"id":"602","name":"psa-range","addressType":"INTERNAL","purpose":"VPC_PEERING","status":"RESERVED","prefixLength":16,
	 "network":"` + netPrefix + `/global/networks/vpc-main"}
]}`

// forwardingRulesAgg is a forwardingRules.aggregatedList page: one external L4 LB
// front-end on tcp:443.
const forwardingRulesAgg = `{"items":{
	"regions/us-central1":{"forwardingRules":[
		{"id":"701","name":"fr-web","IPAddress":"34.10.20.30","IPProtocol":"TCP","portRange":"443-443","loadBalancingScheme":"EXTERNAL","networkTier":"PREMIUM",
		 "region":"` + netPrefix + `/regions/us-central1","backendService":"` + netPrefix + `/regions/us-central1/backendServices/bes-web"}
	]}
}}`

// globalForwardingRulesList is a globalForwardingRules.list page: one global HTTPS LB
// front-end pointing at a target proxy.
const globalForwardingRulesList = `{"items":[
	{"id":"702","name":"gfr-https","IPAddress":"203.0.113.5","IPProtocol":"TCP","portRange":"443-443","loadBalancingScheme":"EXTERNAL_MANAGED",
	 "target":"` + netPrefix + `/global/targetHttpsProxies/proxy-web"}
]}`

// fullEdgeStub returns a stub with empty core resources and the five edge resources
// populated, so an edge test exercises only the new resources.
func fullEdgeStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"global/networks":            `{"items":[]}`,
		"aggregated/subnetworks":     `{"items":{}}`,
		"global/firewalls":           `{"items":[]}`,
		"global/routes":              `{"items":[]}`,
		"aggregated/routers":         routersAgg,
		"aggregated/addresses":       addressesAgg,
		"global/addresses":           globalAddressesList,
		"aggregated/forwardingRules": forwardingRulesAgg,
		"global/forwardingRules":     globalForwardingRulesList,
	}}
}

// TestNetworkMapsRouters proves a Cloud Router becomes a gateway node keyed by
// region, with its Cloud NAT config as a canonical-JSON fact, and the aggregatedList
// unreachable scope makes compute.routers Partial.
func TestNetworkMapsRouters(t *testing.T) {
	s := runNetwork(t, "proj", fullEdgeStub())
	r, ok := netNode(s, model.NodeGateway, "rtr-a")
	if !ok {
		t.Fatal("rtr-a not emitted as a gateway node")
	}
	if r.NativeID != "//compute.googleapis.com/projects/proj/regions/us-central1/routers/rtr-a" {
		t.Errorf("rtr-a keyed by %q", r.NativeID)
	}
	for k, v := range map[string]string{"network": "vpc-main", "region": "us-central1", "bgp_peer_count": "1", "interface_count": "2"} {
		if r.Attributes[k] != v {
			t.Errorf("rtr-a %s = %q, want %q", k, r.Attributes[k], v)
		}
	}
	if nats := r.Attributes["nats"]; !strings.Contains(nats, `"name":"nat-a"`) || !strings.Contains(nats, `"type":"PUBLIC"`) || !strings.Contains(nats, `"nat_ip_allocate_option":"AUTO_ONLY"`) || !strings.Contains(nats, `"log_enabled":true`) {
		t.Errorf("nats fact = %q", nats)
	}
	if c := completenessOf(s, "compute.routers"); c.Status != collect.Partial || c.Reason != "unreachable: regions/asia-south2" {
		t.Errorf("compute.routers = %+v, want partial unreachable", c)
	}
}

// TestNetworkMapsAddresses proves regional and global reserved addresses both become
// endpoint nodes with the right region attribute and users recorded as a fact.
func TestNetworkMapsAddresses(t *testing.T) {
	s := runNetwork(t, "proj", fullEdgeStub())
	ext, ok := netNode(s, model.NodeEndpoint, "ext-a")
	if !ok {
		t.Fatal("ext-a not emitted as an endpoint node")
	}
	if ext.NativeID != "//compute.googleapis.com/projects/proj/regions/us-central1/addresses/ext-a" {
		t.Errorf("ext-a keyed by %q", ext.NativeID)
	}
	for k, v := range map[string]string{
		"address": "34.10.20.30", "address_type": "EXTERNAL", "status": "IN_USE",
		"network_tier": "PREMIUM", "region": "us-central1", "users": "web-1",
	} {
		if ext.Attributes[k] != v {
			t.Errorf("ext-a %s = %q, want %q", k, ext.Attributes[k], v)
		}
	}
	// A global address reports no region: it is keyed under global and the region
	// attribute reads "global".
	psa, ok := netNode(s, model.NodeEndpoint, "psa-range")
	if !ok {
		t.Fatal("psa-range global address not emitted")
	}
	if psa.NativeID != "//compute.googleapis.com/projects/proj/global/addresses/psa-range" {
		t.Errorf("psa-range keyed by %q", psa.NativeID)
	}
	for k, v := range map[string]string{"address_type": "INTERNAL", "purpose": "VPC_PEERING", "region": "global", "prefix_length": "16"} {
		if psa.Attributes[k] != v {
			t.Errorf("psa-range %s = %q, want %q", k, psa.Attributes[k], v)
		}
	}
}

// TestNetworkMapsForwardingRules proves regional and global forwarding rules both
// become gateway nodes with the ingress facts (address, protocol, scheme, target or
// backend) recorded.
func TestNetworkMapsForwardingRules(t *testing.T) {
	s := runNetwork(t, "proj", fullEdgeStub())
	fr, ok := netNode(s, model.NodeGateway, "fr-web")
	if !ok {
		t.Fatal("fr-web not emitted as a gateway node")
	}
	if fr.NativeID != "//compute.googleapis.com/projects/proj/regions/us-central1/forwardingRules/fr-web" {
		t.Errorf("fr-web keyed by %q", fr.NativeID)
	}
	for k, v := range map[string]string{
		"ip_address": "34.10.20.30", "ip_protocol": "TCP", "port_range": "443-443",
		"load_balancing_scheme": "EXTERNAL", "region": "us-central1", "backend_service": "bes-web",
	} {
		if fr.Attributes[k] != v {
			t.Errorf("fr-web %s = %q, want %q", k, fr.Attributes[k], v)
		}
	}
	gfr, ok := netNode(s, model.NodeGateway, "gfr-https")
	if !ok {
		t.Fatal("gfr-https global forwarding rule not emitted")
	}
	for k, v := range map[string]string{
		"ip_address": "203.0.113.5", "load_balancing_scheme": "EXTERNAL_MANAGED",
		"region": "global", "target": "proxy-web",
	} {
		if gfr.Attributes[k] != v {
			t.Errorf("gfr-https %s = %q, want %q", k, gfr.Attributes[k], v)
		}
	}
}

// TestNetworkEdgeAllComplete proves the five edge resources each record a
// completeness (four Complete, routers Partial for its unreachable scope) and that
// the global-vs-aggregated split counts every item.
func TestNetworkEdgeAllComplete(t *testing.T) {
	s := runNetwork(t, "proj", fullEdgeStub())
	for svc, n := range map[string]int{
		"compute.addresses": 1, "compute.globalAddresses": 1,
		"compute.forwardingRules": 1, "compute.globalForwardingRules": 1,
	} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != n {
			t.Errorf("%s = %+v, want complete/%d", svc, c, n)
		}
	}
	if c := completenessOf(s, "compute.routers"); c.Status != collect.Partial || c.Collected != 1 {
		t.Errorf("compute.routers = %+v, want partial/1", c)
	}
}

// TestNetworkGlobalForwardingRulesPaginate proves nextPageToken is followed for a
// global edge list.
func TestNetworkGlobalForwardingRulesPaginate(t *testing.T) {
	api := fullEdgeStub()
	api.bodies["global/forwardingRules"] = `{"items":[{"name":"g1","IPAddress":"1.2.3.4"}],"nextPageToken":"gp2"}`
	api.bodies["gp2"] = `{"items":[{"name":"g2","IPAddress":"1.2.3.5"}]}`
	s := runNetwork(t, "proj", api)
	if c := completenessOf(s, "compute.globalForwardingRules"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("compute.globalForwardingRules = %+v, want complete/2 across pages", c)
	}
}

// TestNetworkEdgeDeniedIsGap proves a denied edge resource is a Denied gap that does
// not fail the run or block the others.
func TestNetworkEdgeDeniedIsGap(t *testing.T) {
	api := fullEdgeStub()
	api.failSub = "aggregated/routers"
	api.failWith = &gcpError{status: 403, body: "PERMISSION_DENIED"}
	var s collect.Scan
	if err := newNetworkCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied edge resource must not fail the run: %v", err)
	}
	if statusOf(s, "compute.routers") != collect.Denied {
		t.Errorf("compute.routers = %s, want denied", statusOf(s, "compute.routers"))
	}
	if statusOf(s, "compute.addresses") != collect.Complete {
		t.Error("compute.addresses should still collect when routers is denied")
	}
}

// TestNetworkEdgeEmptyIsComplete proves an empty project is an honest Complete/0 for
// every edge resource, not a gap.
func TestNetworkEdgeEmptyIsComplete(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"global/networks": `{"items":[]}`, "aggregated/subnetworks": `{"items":{}}`,
		"global/firewalls": `{"items":[]}`, "global/routes": `{"items":[]}`,
		"aggregated/routers": `{"items":{}}`, "aggregated/addresses": `{"items":{}}`,
		"global/addresses": `{"items":[]}`, "aggregated/forwardingRules": `{"items":{}}`,
		"global/forwardingRules": `{"items":[]}`,
	}}
	s := runNetwork(t, "proj", api)
	for _, svc := range []string{"compute.routers", "compute.addresses", "compute.globalAddresses", "compute.forwardingRules", "compute.globalForwardingRules"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}
