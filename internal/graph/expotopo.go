package graph

import (
	"fmt"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// netIndex is the reconstructed networking topology: the lookups the per-cloud
// exposure joins need, built once from the entity set by parsing the forward-key
// facts the collectors emit (there are no reachability edges to follow, ADR-0024).
type netIndex struct {
	ent           map[string]model.Entity
	naclForSubnet map[string]string // AWS subnet native id -> its network ACL's entries JSON
	gcpFirewalls  []model.Entity    // GCP firewall nodes (NodeControl with allow/deny rule facts)
	gaps          []string          // per-resource honesty gaps found during evaluation (merged into the result)
}

func newNetIndex(ent map[string]model.Entity) *netIndex {
	idx := &netIndex{ent: ent, naclForSubnet: map[string]string{}}
	for _, e := range ent {
		if e.Attributes["aws_type"] == "network_acl" {
			for _, sub := range splitList(e.Attributes["associated_subnet_ids"]) {
				idx.naclForSubnet[sub] = e.Attributes["entries"]
			}
		}
		if e.Type == model.NodeControl && strings.HasPrefix(e.NativeID, "//compute.googleapis.com/") &&
			(e.Attributes["allowed_rules"] != "" || e.Attributes["denied_rules"] != "") {
			idx.gcpFirewalls = append(idx.gcpFirewalls, e)
		}
	}
	return idx
}

// splitList splits a comma-joined fact into non-empty trimmed elements.
func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// awsInstanceExposure: the security group is the gate (default-deny: no rule means
// no inbound); the network ACL, default allow-all, intersects only when the subnet
// has one. A non-public instance is modeled but exposes nothing.
func (idx *netIndex) awsInstanceExposure(e model.Entity) ([]portSpan, []string, bool) {
	if e.Attributes["public_ip"] == "" {
		return nil, nil, true
	}
	var sgRules []netRule
	for _, sg := range splitList(e.Attributes["security_group_ids"]) {
		if n, ok := idx.ent[sg]; ok {
			sgRules = append(sgRules, parseAWSSecurityGroupIngress(n.Attributes["ingress_rules"])...)
		}
	}
	sgOpen := internetOpenPorts(sgRules)
	if len(sgOpen) == 0 {
		return nil, nil, true // default-deny security group opens nothing
	}
	open := sgOpen
	trace := []string{exposureTrace(e.NativeID, "security group", sgOpen)}
	if entries, ok := idx.naclForSubnet[e.Attributes["subnet_id"]]; ok {
		naclOpen := internetOpenPorts(parseAWSNaclIngress(entries))
		open = intersectSpans(sgOpen, naclOpen)
		trace = append(trace, exposureTrace(e.NativeID, "network ACL", naclOpen))
	}
	return open, trace, true
}

// azureVMExposure evaluates an Azure VM's inbound internet exposure. When an NSG is
// associated (to a NIC or its subnet), its rules govern (Azure's DenyAllInbound
// default rule, which lives inside the NSG, is the baseline); when both a NIC NSG
// and a subnet NSG apply, both must allow (intersection). When there is NO NSG at
// all, the decision depends on the public IP SKU, not on a default-deny that does
// not exist (see azureNoNSGExposure). A VM with no public IP is not internet-open.
func (idx *netIndex) azureVMExposure(e model.Entity) ([]portSpan, []string, bool) {
	var layers [][]portSpan
	var trace []string
	var pubIPIDs []string
	for _, nicID := range splitList(e.Attributes["network_interface_ids"]) {
		nic, ok := idx.ent[nicID]
		if !ok {
			continue
		}
		pubIPIDs = append(pubIPIDs, splitList(nic.Attributes["public_ip_ids"])...)
		for _, nsgID := range []string{nic.Attributes["nsg_id"], idx.subnetNSG(nic)} {
			if nsgID == "" {
				continue
			}
			if nsg, ok := idx.ent[nsgID]; ok {
				open := internetOpenPorts(parseAzureNSGInbound(nsg.Attributes["security_rules"]))
				layers = append(layers, open)
				trace = append(trace, exposureTrace(e.NativeID, "NSG "+nsg.NativeID, open))
			}
		}
	}
	if len(pubIPIDs) == 0 {
		return nil, nil, true // no public IP: not internet-reachable
	}
	if len(layers) == 0 {
		return idx.azureNoNSGExposure(e, pubIPIDs) // no NSG: outcome depends on public IP SKU
	}
	open := layers[0]
	for _, l := range layers[1:] {
		open = intersectSpans(open, l)
	}
	return open, trace, true
}

// azureNoNSGExposure decides inbound exposure for an Azure VM that has a public IP
// but no NSG on any NIC or subnet. With no NSG there is no DenyAllInbound rule (that
// default rule exists only inside a network security group), so the outcome depends
// on the public IP SKU, verified against Azure documentation: a Standard SKU public
// IP is secure by default (inbound blocked), while a Basic SKU public IP is open by
// default (inbound unfiltered, all ports reachable at the network layer). An
// undetermined SKU (the public IP node is absent, or its sku is neither Standard nor
// Basic) is never read as safe: it is reported as an exposure floor with a cited
// gap, honoring the same honest-absence discipline as every other engine here.
func (idx *netIndex) azureNoNSGExposure(e model.Entity, pubIPIDs []string) ([]portSpan, []string, bool) {
	allPorts := []portSpan{{Proto: "all", AllPorts: true}}
	var basicID, unknownID string
	for _, id := range pubIPIDs {
		ip, ok := idx.ent[id]
		if !ok {
			unknownID = id
			continue
		}
		switch strings.ToLower(ip.Attributes["sku"]) {
		case "basic":
			basicID = ip.NativeID
		case "standard":
			// Standard SKU public IP with no NSG is secure by default.
		default:
			if unknownID == "" {
				unknownID = ip.NativeID
			}
		}
	}
	switch {
	case basicID != "":
		return allPorts, []string{fmt.Sprintf("%s: public IP %s is Basic SKU with no network security group; inbound is open by default (all ports)", e.NativeID, basicID)}, true
	case unknownID != "":
		idx.gaps = append(idx.gaps, fmt.Sprintf("azure vm %s: public IP %s has no NSG and an undetermined SKU; reported as an exposure floor (a Basic SKU would be open, a Standard SKU secure by default)", e.NativeID, unknownID))
		return allPorts, []string{fmt.Sprintf("%s: public IP %s has no network security group and an undetermined SKU; exposure floor pending SKU", e.NativeID, unknownID)}, true
	default:
		return nil, nil, true // every public IP is Standard SKU: secure by default
	}
}

// subnetNSG returns the NSG id associated with a NIC's subnet, if any.
func (idx *netIndex) subnetNSG(nic model.Entity) string {
	for _, sub := range splitList(nic.Attributes["subnet_ids"]) {
		if s, ok := idx.ent[sub]; ok {
			if id := s.Attributes["nsg_id"]; id != "" {
				return id
			}
		}
	}
	return ""
}

// gcpInstanceExposure: ingress is implied deny-all, so only firewalls that allow an
// internet source open a port; denies are honored by priority within the matched
// set. A firewall matches when it is on the instance's network and its target tags
// are empty or intersect the instance's network tags.
func (idx *netIndex) gcpInstanceExposure(e model.Entity) ([]portSpan, []string, bool) {
	if e.Attributes["public_ip"] == "" {
		return nil, nil, true
	}
	network := e.Attributes["network"]
	tags := splitList(e.Attributes["network_tags"])
	var rules []netRule
	for _, fw := range idx.gcpFirewalls {
		if fw.Attributes["network"] != network {
			continue
		}
		if targets := splitList(fw.Attributes["target_tags"]); len(targets) > 0 && !intersects(targets, tags) {
			continue
		}
		prio := atoiOr(fw.Attributes["priority"], 1000)
		rules = append(rules, parseGCPFirewall(fw.Attributes["allowed_rules"], fw.Attributes["denied_rules"],
			fw.Attributes["direction"], fw.Attributes["source_ranges"], prio)...)
	}
	open := internetOpenPorts(rules)
	if len(open) == 0 {
		return nil, nil, true
	}
	return open, []string{exposureTrace(e.NativeID, "firewall rules", open)}, true
}

func intersects(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

func atoiOr(s string, def int) int {
	n := 0
	if s == "" {
		return def
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}
