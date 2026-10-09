package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

func entAttr(g *normalize.NormalizedScan, nativeID string) map[string]string {
	id := sid(nativeID)
	for _, e := range g.Entities {
		if e.ID == id {
			return e.Attributes
		}
	}
	return nil
}

// TestMaterializeSetsExposureFacts proves the bridge projects reachability onto the
// exposed entity as facts the closed-predicate detection engine can read: an
// all-ports exposure sets internet_exposed_all_ports, a scoped exposure does not, and
// exposure_provider identifies the cloud for per-cloud rule scoping.
func TestMaterializeSetsExposureFacts(t *testing.T) {
	// All-ports: an SG allowing every protocol/port from 0.0.0.0/0.
	instAll := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-all", map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-all"})
	sgAll := node(model.NodeControl, "sg-all", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"-1","from_port":0,"to_port":0,"cidr":"0.0.0.0/0"}]`})
	g := norm(awsNet(instAll, sgAll))
	Materialize(g)
	a := entAttr(g, "arn:aws:ec2:u:1:instance/i-all")
	if a["internet_exposed"] != "true" {
		t.Errorf("internet_exposed = %q, want true", a["internet_exposed"])
	}
	if a["internet_exposed_all_ports"] != "true" {
		t.Errorf("internet_exposed_all_ports = %q, want true", a["internet_exposed_all_ports"])
	}
	if a["exposure_provider"] != "aws" {
		t.Errorf("exposure_provider = %q, want aws", a["exposure_provider"])
	}

	// Scoped: an SG allowing only tcp/443 from the internet. Exposed, but not all ports.
	instScoped := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-443", map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-443"})
	sg443 := node(model.NodeControl, "sg-443", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidr":"0.0.0.0/0"}]`})
	g2 := norm(awsNet(instScoped, sg443))
	Materialize(g2)
	a2 := entAttr(g2, "arn:aws:ec2:u:1:instance/i-443")
	if a2["internet_exposed"] != "true" {
		t.Errorf("scoped: internet_exposed = %q, want true", a2["internet_exposed"])
	}
	if a2["internet_exposed_all_ports"] != "" {
		t.Errorf("scoped: internet_exposed_all_ports = %q, want unset", a2["internet_exposed_all_ports"])
	}
	if a2["internet_exposed_ports"] != "tcp/443" {
		t.Errorf("scoped: internet_exposed_ports = %q, want tcp/443", a2["internet_exposed_ports"])
	}
}

// TestMaterializeOnlyAddsAndSkipsUnexposed proves Materialize does not touch
// pre-existing facts and does not stamp entities that are not exposed.
func TestMaterializeOnlyAddsAndSkipsUnexposed(t *testing.T) {
	// A private instance (no public IP) is not exposed and must be left untouched.
	priv := node(model.NodeCompute, "arn:aws:ec2:u:1:instance/i-priv", map[string]string{"security_group_ids": "sg-x", "name_tag": "keep-me"})
	sg := node(model.NodeControl, "sg-x", map[string]string{"aws_type": "security_group", "ingress_rules": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidr":"0.0.0.0/0"}]`})
	g := norm(awsNet(priv, sg))
	Materialize(g)
	a := entAttr(g, "arn:aws:ec2:u:1:instance/i-priv")
	if a["internet_exposed"] != "" || a["exposure_provider"] != "" {
		t.Errorf("private instance was stamped: %+v", a)
	}
	if a["name_tag"] != "keep-me" {
		t.Errorf("pre-existing fact clobbered: name_tag = %q", a["name_tag"])
	}
}
