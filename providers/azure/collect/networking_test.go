package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	vnetID   = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vnet1"
	subnetID = vnetID + "/subnets/web"
	nsgID    = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1"
	nicID    = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/nic1"
	pipID    = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip1"
	rtID     = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/routeTables/rt1"
)

// oneVNet is a virtualNetworks.list page: one VNet with one subnet that names its
// network security group (the subnet side of the NSG association) and route table.
const oneVNet = `{"value":[
	{"id":"` + vnetID + `","name":"vnet1","location":"eastus","tags":{"env":"prod"},
	 "properties":{
	   "addressSpace":{"addressPrefixes":["10.0.0.0/16"]},
	   "enableDdosProtection":false,
	   "virtualNetworkPeerings":[{"id":"peer1"}],
	   "subnets":[
	     {"id":"` + subnetID + `","name":"web","properties":{"addressPrefix":"10.0.1.0/24","networkSecurityGroup":{"id":"` + nsgID + `"},"routeTable":{"id":"` + rtID + `"}}}
	   ]}}
]}`

// oneNSG is a networkSecurityGroups.list page: one NSG with two rules (deliberately
// out of priority order to prove sorting) and, on its own side, the subnet and the
// network interface it is attached to.
const oneNSG = `{"value":[
	{"id":"` + nsgID + `","name":"nsg1","location":"eastus",
	 "properties":{
	   "securityRules":[
	     {"name":"allow-https","properties":{"priority":200,"direction":"Inbound","access":"Allow","protocol":"Tcp","sourceAddressPrefix":"*","destinationAddressPrefix":"*","destinationPortRange":"443"}},
	     {"name":"allow-web","properties":{"priority":100,"direction":"Inbound","access":"Allow","protocol":"Tcp","sourceAddressPrefixes":["10.0.0.0/8","192.168.0.0/16"],"destinationPortRanges":["80","8080"]}}
	   ],
	   "subnets":[{"id":"` + subnetID + `"}],
	   "networkInterfaces":[{"id":"` + nicID + `"}]}}
]}`

// onePublicIP is a publicIPAddresses.list page: one static Standard public IP bound
// to the NIC's ip configuration.
const onePublicIP = `{"value":[
	{"id":"` + pipID + `","name":"pip1","location":"eastus","sku":{"name":"Standard"},
	 "properties":{"ipAddress":"20.1.2.3","publicIPAllocationMethod":"Static","ipConfiguration":{"id":"` + nicID + `/ipConfigurations/ipconfig1"},"dnsSettings":{"fqdn":"app.eastus.cloudapp.azure.com"}}}
]}`

// oneNIC is a networkInterfaces.list page: one NIC with a private IP, a public IP and
// subnet reference, its network security group (the NIC side of the association), and
// the virtual machine it is attached to (joins onto the compute collector's node).
const oneNIC = `{"value":[
	{"id":"` + nicID + `","name":"nic1","location":"eastus",
	 "properties":{
	   "ipConfigurations":[{"properties":{"privateIPAddress":"10.0.1.4","subnet":{"id":"` + subnetID + `"},"publicIPAddress":{"id":"` + pipID + `"}}}],
	   "networkSecurityGroup":{"id":"` + nsgID + `"},
	   "virtualMachine":{"id":"` + vmID + `"}}}
]}`

func networkStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?":       subsOne,
		"virtualNetworks":       oneVNet,
		"networkSecurityGroups": oneNSG,
		"publicIPAddresses":     onePublicIP,
		"networkInterfaces":     oneNIC,
	}}
}

func runNetwork(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newNetworkCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestNetworkMapsVNetAndSubnets proves a virtual network and its embedded subnet each
// become a network node keyed by ARM resource id, with the subnet carrying its parent
// vnet and route table as id facts.
func TestNetworkMapsVNetAndSubnets(t *testing.T) {
	s := runNetwork(t, networkStub())

	v, ok := nodeNamed(s, model.NodeNetwork, vnetID)
	if !ok {
		t.Fatal("vnet1 not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "virtual_network", "location": "eastus", "address_prefixes": "10.0.0.0/16",
		"ddos_protection": "false", "peering_count": "1", "tag:env": "prod",
	} {
		if v.Attributes[k] != want {
			t.Errorf("vnet1 %s = %q, want %q", k, v.Attributes[k], want)
		}
	}

	sn, ok := nodeNamed(s, model.NodeNetwork, subnetID)
	if !ok {
		t.Fatal("subnet web not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "subnet", "vnet_id": vnetID, "address_prefix": "10.0.1.0/24",
		"nsg_id": nsgID, "route_table_id": rtID,
	} {
		if sn.Attributes[k] != want {
			t.Errorf("subnet %s = %q, want %q", k, sn.Attributes[k], want)
		}
	}
	if c := completenessOf(s, "network.virtualNetworks"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("network.virtualNetworks = %+v, want complete/1", c)
	}
}

// TestNetworkNSGDualAttachment proves the one genuinely new modeling piece: an NSG
// attaches to both a subnet and a network interface, and that association is recorded
// on every side. The NSG control node lists its associated subnet and NIC; the subnet
// node and the NIC node each name the NSG. No effective-rule verdict is synthesized.
func TestNetworkNSGDualAttachment(t *testing.T) {
	s := runNetwork(t, networkStub())

	// The NSG side.
	g, ok := nodeNamed(s, model.NodeControl, nsgID)
	if !ok {
		t.Fatal("nsg1 not emitted as a control node keyed by ARM resource id")
	}
	if g.Attributes["associated_subnets"] != subnetID {
		t.Errorf("nsg associated_subnets = %q, want %q", g.Attributes["associated_subnets"], subnetID)
	}
	if g.Attributes["associated_nics"] != nicID {
		t.Errorf("nsg associated_nics = %q, want %q", g.Attributes["associated_nics"], nicID)
	}

	// The subnet side.
	if sn, _ := nodeNamed(s, model.NodeNetwork, subnetID); sn.Attributes["nsg_id"] != nsgID {
		t.Errorf("subnet nsg_id = %q, want %q", sn.Attributes["nsg_id"], nsgID)
	}
	// The NIC side.
	if n, _ := nodeNamed(s, model.NodeEndpoint, nicID); n.Attributes["nsg_id"] != nsgID {
		t.Errorf("nic nsg_id = %q, want %q", n.Attributes["nsg_id"], nsgID)
	}

	// Rules recorded as canonical JSON, sorted by priority (allow-web 100 before
	// allow-https 200), single and array rule fields merged.
	rules := g.Attributes["security_rules"]
	if i, j := strings.Index(rules, "allow-web"), strings.Index(rules, "allow-https"); i < 0 || j < 0 || i > j {
		t.Errorf("security_rules not sorted by priority: %s", rules)
	}
	if !strings.Contains(rules, `"source_prefixes":["10.0.0.0/8","192.168.0.0/16"]`) {
		t.Errorf("array source prefixes not carried: %s", rules)
	}
	if !strings.Contains(rules, `"destination_ports":["443"]`) {
		t.Errorf("single destination port not merged into the array form: %s", rules)
	}
	for _, forbidden := range []string{"is_public", "exposed", "effective_access", "compliant"} {
		if _, bad := g.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
}

// TestNetworkMapsPublicIPAndNIC proves public IPs and NICs become endpoint nodes with
// their reachability-relevant facts, including the NIC's join keys to its subnet,
// public IP, and virtual machine.
func TestNetworkMapsPublicIPAndNIC(t *testing.T) {
	s := runNetwork(t, networkStub())

	ip, ok := nodeNamed(s, model.NodeEndpoint, pipID)
	if !ok {
		t.Fatal("pip1 not emitted as an endpoint node")
	}
	for k, want := range map[string]string{
		"azure_type": "public_ip_address", "sku": "Standard", "ip_address": "20.1.2.3",
		"allocation_method": "Static", "fqdn": "app.eastus.cloudapp.azure.com",
	} {
		if ip.Attributes[k] != want {
			t.Errorf("pip1 %s = %q, want %q", k, ip.Attributes[k], want)
		}
	}

	n, ok := nodeNamed(s, model.NodeEndpoint, nicID)
	if !ok {
		t.Fatal("nic1 not emitted as an endpoint node")
	}
	for k, want := range map[string]string{
		"azure_type": "network_interface", "private_ips": "10.0.1.4",
		"public_ip_ids": pipID, "subnet_ids": subnetID, "virtual_machine_id": vmID,
	} {
		if n.Attributes[k] != want {
			t.Errorf("nic1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
}

// TestNetworkDeniedIsGap proves a denied read is a Denied gap (never a pass) that does
// not fail the run and emits no nodes for that resource type.
func TestNetworkDeniedIsGap(t *testing.T) {
	api := networkStub()
	api.failSub = "networkSecurityGroups"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newNetworkCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied NSG read must not fail the run: %v", err)
	}
	if statusOf(s, "network.networkSecurityGroups") != collect.Denied {
		t.Errorf("network.networkSecurityGroups = %s, want denied", statusOf(s, "network.networkSecurityGroups"))
	}
	if _, ok := nodeNamed(s, model.NodeControl, nsgID); ok {
		t.Error("a denied NSG read must not emit control nodes")
	}
}

// TestNetworkEmptyIsComplete proves an empty subscription is an honest Complete/0 for
// every resource type, never a silent skip.
func TestNetworkEmptyIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne}}
	s := runNetwork(t, api)
	for _, svc := range []string{"network.virtualNetworks", "network.networkSecurityGroups", "network.publicIPAddresses", "network.networkInterfaces"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestNetworkPaginates proves nextLink is followed across pages.
func TestNetworkPaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":    subsOne,
		"networkInterfaces?": `{"value":[{"id":"` + nicID + `a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":                `{"value":[{"id":"` + nicID + `b","name":"b"}]}`,
	}}
	s := runNetwork(t, api)
	nics := 0
	for _, n := range s.Nodes {
		if n.Attributes["azure_type"] == "network_interface" {
			nics++
		}
	}
	if nics != 2 {
		t.Errorf("NICs across pages = %d, want 2", nics)
	}
}

// TestNetworkBudgetExhaustion proves the shared budget bounds the sweep.
func TestNetworkBudgetExhaustion(t *testing.T) {
	c := newNetworkCollector("tenant-1", networkStub())
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "network.virtualNetworks"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("network.virtualNetworks = %+v, want partial budget-exhausted", got)
	}
}

// TestNetworkEvidenceRedactsToken proves the evidence body is scrubbed.
func TestNetworkEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"virtualNetworks": `{"value":[{"id":"` + vnetID + `","name":"` + token + `"}]}`,
	}}
	s := runNetwork(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
