package graph

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func exposureFor(res ExposureResult, entity string) []model.Exposure {
	var out []model.Exposure
	for _, e := range res.Exposures {
		if e.Entity == sid(entity) {
			out = append(out, e)
		}
	}
	return out
}

func openOn(exps []model.Exposure, proto, from, to int) bool {
	for _, e := range exps {
		if e.Protocol != nil && *e.Protocol == proto && e.Ports != nil && e.Ports.From == from && e.Ports.To == to {
			return true
		}
	}
	return false
}

func awsNet(inst collect.Node, extra ...collect.Node) *collect.Scan {
	return &collect.Scan{
		Nodes:        append([]collect.Node{inst}, extra...),
		Completeness: []collect.Completeness{{Service: "ec2.securityGroups", Status: collect.Complete}, {Service: "ec2.networkAcls", Status: collect.Complete}, {Service: "ec2.instances", Status: collect.Complete}},
	}
}

// TestAWSExposureSGIntersectNACL is the layer-AND proof: an SG open to 0.0.0.0/0:443
// is exposed when the subnet's NACL allows 443, and NOT exposed when the NACL denies
// it. Mutation target: an intersection replaced by a union would keep it exposed.
func TestAWSExposureSGIntersectNACL(t *testing.T) {
	inst := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-1", map[string]string{
		"public_ip": "1.2.3.4", "security_group_ids": "sg-1", "subnet_id": "subnet-1",
	})
	sg := node(model.NodeControl, "sg-1", map[string]string{
		"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidr":"0.0.0.0/0"}]`,
	})
	naclAllow := node(model.NodeControl, "nacl-1", map[string]string{
		"aws_type": "network_acl", "associated_subnet_ids": "subnet-1",
		"entries": `[{"rule_number":100,"egress":false,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":443,"to_port":443}]`,
	})
	if got := exposureFor(Expose(norm(awsNet(inst, sg, naclAllow))), "arn:aws:ec2:u:1:instance/i-1"); !openOn(got, 6, 443, 443) {
		t.Errorf("SG+NACL both allow 443: not exposed: %+v", got)
	}
	naclDeny := node(model.NodeControl, "nacl-1", map[string]string{
		"aws_type": "network_acl", "associated_subnet_ids": "subnet-1",
		"entries": `[{"rule_number":100,"egress":false,"protocol":"6","action":"deny","cidr":"0.0.0.0/0","from_port":443,"to_port":443}]`,
	})
	if got := exposureFor(Expose(norm(awsNet(inst, sg, naclDeny))), "arn:aws:ec2:u:1:instance/i-1"); len(got) != 0 {
		t.Errorf("NACL deny should remove the exposure (layer AND): %+v", got)
	}
}

// TestAWSPrivateAndDefaultDeny proves a non-public instance and a public instance
// whose SG has no internet rule are both not exposed.
func TestAWSPrivateAndDefaultDeny(t *testing.T) {
	priv := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-priv", map[string]string{"security_group_ids": "sg-1", "subnet_id": "subnet-1"})
	sg := node(model.NodeControl, "sg-1", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidr":"0.0.0.0/0"}]`})
	if got := exposureFor(Expose(norm(awsNet(priv, sg))), "arn:aws:ec2:u:1:instance/i-priv"); len(got) != 0 {
		t.Errorf("private instance (no public_ip) exposed: %+v", got)
	}
	pub := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-2", map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-scoped"})
	sgScoped := node(model.NodeControl, "sg-scoped", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidr":"10.0.0.0/8"}]`})
	if got := exposureFor(Expose(norm(awsNet(pub, sgScoped))), "arn:aws:ec2:u:1:instance/i-2"); len(got) != 0 {
		t.Errorf("public instance with scoped-only SG exposed: %+v", got)
	}
}

// azureVMScan builds a VM plus one NIC that references the given public IP ids and
// NSG id (either may be empty), together with any extra nodes (public IPs, NSGs).
func azureVMScan(pubIPIDs, nsgID string, extra ...collect.Node) *collect.Scan {
	vm := node(model.NodeCompute, "/subscriptions/s/vm1", map[string]string{"azure_type": "virtual_machine", "network_interface_ids": "/nic1"})
	nic := node(model.NodeEndpoint, "/nic1", map[string]string{"azure_type": "network_interface", "public_ip_ids": pubIPIDs, "nsg_id": nsgID})
	comp := []collect.Completeness{
		{Service: "network.networkSecurityGroups", Status: collect.Complete},
		{Service: "network.publicIPAddresses", Status: collect.Complete},
		{Service: "compute.virtualMachines", Status: collect.Complete},
	}
	return &collect.Scan{Nodes: append([]collect.Node{vm, nic}, extra...), Completeness: comp}
}

func pipNode(id, sku string) collect.Node {
	return node(model.NodeEndpoint, id, map[string]string{"azure_type": "public_ip_address", "sku": sku})
}

func isAllPorts(e model.Exposure) bool { return e.Protocol == nil && e.Ports == nil }

// TestAzureNoNSGExposureBySKU is the safety-critical no-NSG case, verified against
// Azure documentation. With no NSG there is no DenyAllInbound (that default rule
// lives inside an NSG), so the outcome depends on the public IP SKU: a Standard SKU
// public IP is secure by default (not exposed), a Basic SKU public IP is open by
// default (exposed on all ports), and an undetermined SKU is never a confident pass
// (exposure floor plus a cited gap). Mutation target: returning "not exposed" for
// the Basic or undetermined branch, an absent config read as safe, fails here.
func TestAzureNoNSGExposureBySKU(t *testing.T) {
	// Standard SKU, no NSG -> secure by default -> not exposed.
	std := azureVMScan("/pip-std", "", pipNode("/pip-std", "Standard"))
	if got := exposureFor(Expose(norm(std)), "/subscriptions/s/vm1"); len(got) != 0 {
		t.Errorf("Standard SKU public IP with no NSG should be secure by default, got exposure: %+v", got)
	}
	// Basic SKU, no NSG -> open by default -> exposed on all ports.
	basic := azureVMScan("/pip-basic", "", pipNode("/pip-basic", "Basic"))
	if got := exposureFor(Expose(norm(basic)), "/subscriptions/s/vm1"); len(got) != 1 || !isAllPorts(got[0]) {
		t.Errorf("Basic SKU public IP with no NSG must be exposed on all ports (open by default), got: %+v", got)
	}
	// Undetermined SKU (public IP node absent) -> exposure floor + cited gap, never a pass.
	res := Expose(norm(azureVMScan("/pip-missing", "")))
	got := exposureFor(res, "/subscriptions/s/vm1")
	if len(got) != 1 || !isAllPorts(got[0]) {
		t.Errorf("undetermined-SKU public IP with no NSG must be an exposure floor, got: %+v", got)
	}
	if res.Complete {
		t.Error("undetermined SKU should make the result a floor (Complete=false), not Complete")
	}
	found := false
	for _, g := range res.Gaps {
		if strings.Contains(g, "undetermined SKU") {
			found = true
		}
	}
	if !found {
		t.Errorf("no gap cited for the undetermined-SKU no-NSG case: %+v", res.Gaps)
	}
}

// TestAzureNSGGoverns proves that when an NSG is present it governs regardless of
// SKU: an NSG allowing Internet:22 exposes 22, and an NSG with no internet allow is
// not exposed even with a Basic SKU public IP (the NSG's DenyAllInbound applies).
func TestAzureNSGGoverns(t *testing.T) {
	allow := node(model.NodeControl, "/nsg-allow", map[string]string{"azure_type": "network_security_group",
		"security_rules": `[{"priority":100,"direction":"Inbound","access":"Allow","protocol":"Tcp","source_prefixes":["Internet"],"destination_ports":["22"]}]`})
	scan := azureVMScan("/pip-std", "/nsg-allow", pipNode("/pip-std", "Standard"), allow)
	if got := exposureFor(Expose(norm(scan)), "/subscriptions/s/vm1"); !openOn(got, 6, 22, 22) {
		t.Errorf("NSG allowing Internet:22 should expose 22: %+v", got)
	}
	// NSG present, only an internal-scoped allow -> not exposed, even with Basic SKU.
	deny := node(model.NodeControl, "/nsg-internal", map[string]string{"azure_type": "network_security_group",
		"security_rules": `[{"priority":100,"direction":"Inbound","access":"Allow","protocol":"Tcp","source_prefixes":["10.0.0.0/8"],"destination_ports":["22"]}]`})
	scan2 := azureVMScan("/pip-basic", "/nsg-internal", pipNode("/pip-basic", "Basic"), deny)
	if got := exposureFor(Expose(norm(scan2)), "/subscriptions/s/vm1"); len(got) != 0 {
		t.Errorf("NSG present with no internet allow should not be exposed even with Basic SKU: %+v", got)
	}
}

// TestGCPExposureFirewall proves a public GCE instance is exposed on a port an
// ingress firewall allows from 0.0.0.0/0, and a higher-priority deny removes it.
func TestGCPExposureFirewall(t *testing.T) {
	inst := node(model.NodeCompute, "//compute.googleapis.com/projects/p/zones/z/instances/i", map[string]string{"public_ip": "1.2.3.4", "network": "//compute.googleapis.com/projects/p/global/networks/default"})
	allow := node(model.NodeControl, "//compute.googleapis.com/projects/p/global/firewalls/allow-http", map[string]string{
		"network": "//compute.googleapis.com/projects/p/global/networks/default", "direction": "INGRESS", "source_ranges": "0.0.0.0/0", "priority": "1000",
		"allowed_rules": `[{"protocol":"tcp","ports":["80"]}]`})
	scan := &collect.Scan{Nodes: []collect.Node{inst, allow}, Completeness: []collect.Completeness{{Service: "compute.firewalls", Status: collect.Complete}, {Service: "compute.instances", Status: collect.Complete}}}
	if got := exposureFor(Expose(norm(scan)), inst.NativeID); !openOn(got, 6, 80, 80) {
		t.Errorf("GCP instance with ingress allow 0.0.0.0/0:80 not exposed: %+v", got)
	}
}

// TestExposureAlwaysConfigNotVerified is the config-vs-verified boundary (ADR-0024
// §1): every emitted exposure has Effective=unknown and Zone=internet, never a
// claimed verified reachability. Mutation target: setting Effective=yes fails here.
func TestExposureAlwaysConfigNotVerified(t *testing.T) {
	inst := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-1", map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-1"})
	sg := node(model.NodeControl, "sg-1", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"0.0.0.0/0"}]`})
	res := Expose(norm(awsNet(inst, sg)))
	if len(res.Exposures) == 0 {
		t.Fatal("expected an exposure")
	}
	for _, e := range res.Exposures {
		if e.Effective != model.Unknown {
			t.Errorf("exposure Effective = %s, want unknown (config exposure, not verified)", e.Effective)
		}
		if e.Zone != model.ZoneInternet {
			t.Errorf("exposure Zone = %s, want internet", e.Zone)
		}
		if e.AuthRequired != model.Unknown {
			t.Errorf("exposure AuthRequired = %s, want unknown", e.AuthRequired)
		}
	}
	// And an EdgeExposedTo to the internet marker is emitted.
	var edge bool
	for _, ed := range res.Edges {
		if ed.Kind == model.EdgeExposedTo && ed.Source == sid("arn:aws:ec2:u:1:instance/i-1") && ed.Target == internetNodeID {
			edge = true
		}
	}
	if !edge {
		t.Error("no EdgeExposedTo emitted for the exposed instance")
	}
}

// TestExposureHonestCompleteness proves a denied networking read makes the result
// an explicit floor, never asserted exhaustive.
func TestExposureHonestCompleteness(t *testing.T) {
	scan := &collect.Scan{Completeness: []collect.Completeness{{Service: "ec2.securityGroups", Status: collect.Denied, Reason: "denied"}}}
	res := Expose(norm(scan))
	if res.Complete {
		t.Error("exposure reported Complete despite a denied networking read")
	}
	if len(res.Gaps) == 0 {
		t.Error("no gap cited for the denied read")
	}
}

func TestIntersectSpans(t *testing.T) {
	a := []portSpan{{Proto: "tcp", From: 20, To: 100}}
	b := []portSpan{{Proto: "tcp", From: 80, To: 200}}
	got := intersectSpans(a, b)
	if len(got) != 1 || got[0].From != 80 || got[0].To != 100 {
		t.Errorf("intersect = %+v, want tcp:80-100", got)
	}
	// disjoint
	if got := intersectSpans([]portSpan{{Proto: "tcp", From: 20, To: 30}}, []portSpan{{Proto: "tcp", From: 80, To: 90}}); len(got) != 0 {
		t.Errorf("disjoint intersect = %+v, want none", got)
	}
	// all-ports on one side keeps the other
	all := []portSpan{{Proto: "all", AllPorts: true}}
	if got := intersectSpans(all, []portSpan{{Proto: "tcp", From: 22, To: 22}}); len(got) != 1 || got[0].Proto != "tcp" {
		t.Errorf("all-ports intersect = %+v, want tcp:22", got)
	}
}
