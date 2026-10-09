package graph

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// exposedInstance is an internet-exposed EC2 instance (public IP + a security group
// open to 0.0.0.0/0 on all ports), so Expose marks it an entry.
func exposedInstance(id string) collect.Node {
	return node(model.NodeCompute, id, map[string]string{"public_ip": "1.2.3.4", "security_group_ids": "sg-open"})
}

var openSG = func() collect.Node {
	return node(model.NodeControl, "sg-open", map[string]string{"aws_type": "security_group",
		"ingress_rules": `[{"protocol":"-1","from_port":0,"to_port":0,"cidr":"0.0.0.0/0"}]`})
}()

func pathScan(nodes []collect.Node, links []collect.Link) *collect.Scan {
	return &collect.Scan{
		Nodes: nodes,
		Links: links,
		Completeness: []collect.Completeness{
			{Service: "ec2.instances", Status: collect.Complete},
			{Service: "ec2.securityGroups", Status: collect.Complete},
			{Service: "ec2.networkAcls", Status: collect.Complete},
			{Service: "iam.identities", Status: collect.Complete},
		},
	}
}

func pathFor(res PathResult, entry, target string) (model.AttackPath, bool) {
	for _, p := range res.Paths {
		if p.Entry == sid(entry) && p.Target == sid(target) {
			return p, true
		}
	}
	return model.AttackPath{}, false
}

// TestPathExposedWorkloadToPrivilegedRole is the core positive: an internet-exposed
// instance that assumes an admin role yields a path entry->role, with the assume hop
// traced and the path confidence the minimum of the exposure and the hop (80, not the
// hop's 100). The confidence assertion is also the min-not-max mutation guard.
func TestPathExposedWorkloadToPrivilegedRole(t *testing.T) {
	inst := "arn:aws:ec2:u:1:instance/i-1"
	role := "arn:aws:iam::1:role/admin"
	scan := pathScan(
		[]collect.Node{exposedInstance(inst), openSG, node(model.NodeRole, role, map[string]string{"privilege_level": "admin"})},
		[]collect.Link{{SourceNativeID: inst, TargetNativeID: role, Kind: model.EdgeAssumes}},
	)
	res := Paths(norm(scan))
	p, ok := pathFor(res, inst, role)
	if !ok {
		t.Fatalf("no path from exposed instance to admin role; paths: %+v", res.Paths)
	}
	if p.Score != 100 {
		t.Errorf("score = %d, want 100 (admin target)", p.Score)
	}
	if p.Confidence != 80 {
		t.Errorf("confidence = %d, want 80 (minimum of exposure 80 and assume 100, never the max)", p.Confidence)
	}
	if len(p.Steps) != 2 || p.Steps[0].Node != sid(inst) || p.Steps[1].Node != sid(role) || p.Steps[1].Via != model.EdgeAssumes {
		t.Errorf("steps not the traced entry->role assume hop: %+v", p.Steps)
	}
	if p.Steps[0].Technique != "T1190" || p.Steps[1].Technique != "T1078" {
		t.Errorf("technique tagging wrong: %+v", p.Steps)
	}
}

// TestPathNeverFabricatesHop is a safety-core guard: an exposed instance and an admin
// role with NO edge between them yields no path (the engine never invents a hop to a
// valuable target).
func TestPathNeverFabricatesHop(t *testing.T) {
	inst := "arn:aws:ec2:u:1:instance/i-1"
	role := "arn:aws:iam::1:role/admin"
	scan := pathScan(
		[]collect.Node{exposedInstance(inst), openSG, node(model.NodeRole, role, map[string]string{"privilege_level": "admin"})},
		nil, // no assumes edge: disconnected
	)
	res := Paths(norm(scan))
	if _, ok := pathFor(res, inst, role); ok {
		t.Error("a path was produced with no connecting edge (a fabricated hop)")
	}
	if len(res.Paths) != 0 {
		t.Errorf("no path should exist without a connecting edge: %+v", res.Paths)
	}
}

// TestPathNoDataTarget is the AP-1 honesty guard: a sensitive data store is not a
// path target (no identity-to-data capability edge exists), so no path is invented to
// it even when it is reachable-looking.
func TestPathNoDataTarget(t *testing.T) {
	inst := "arn:aws:ec2:u:1:instance/i-1"
	bucket := "arn:aws:s3:::sensitive"
	scan := pathScan(
		[]collect.Node{exposedInstance(inst), openSG,
			node(model.NodeDataStore, bucket, map[string]string{"tag:data_classification": "restricted"})},
		[]collect.Link{{SourceNativeID: inst, TargetNativeID: bucket, Kind: model.EdgeAssumes}}, // even a spurious edge
	)
	res := Paths(norm(scan))
	if _, ok := pathFor(res, inst, bucket); ok {
		t.Error("a data store was treated as a path target; only privileged identities/roles are targets (AP-1)")
	}
}

// TestPathHonestCompleteness proves a denied read makes the path set an explicit
// floor, never asserted exhaustive.
func TestPathHonestCompleteness(t *testing.T) {
	scan := &collect.Scan{Completeness: []collect.Completeness{{Service: "iam.identities", Status: collect.Denied, Reason: "denied"}}}
	res := Paths(norm(scan))
	if res.Complete {
		t.Error("paths reported Complete despite a denied read")
	}
	if len(res.Gaps) == 0 {
		t.Error("no gap cited for the denied read")
	}
}
