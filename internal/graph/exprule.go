package graph

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/netmatch"
)

// netRule is the normalized form of one firewall / security-group / NSG / NACL
// rule from any cloud, reduced to what deciding internet exposure needs: whether
// it allows or denies, whether its source admits the internet, the protocol and
// port span it covers, and an evaluation order. Normalizing the three collected
// schemas (AWS security groups + network ACLs, Azure NSGs, GCP firewalls) into
// this one shape is the reachability engine's second step (ADR-0024 §4); the per-cloud evaluation order
// is applied faithfully in internetOpenPorts.
type netRule struct {
	allow       bool
	internetSrc bool // the rule's source admits the public internet
	proto       string
	allPorts    bool
	fromPort    int
	toPort      int
	order       int  // NACL rule_number or NSG/GCP priority; lower is evaluated first
	ordered     bool // whether order is meaningful (NACL/NSG/GCP) vs unordered (AWS SG allow-union)
}

// portSpan is a protocol and contiguous port range an internet source can reach.
type portSpan struct {
	Proto    string
	AllPorts bool
	From     int
	To       int
}

// internetSource reports whether a rule source string admits the public internet:
// the IPv4/IPv6 default route, the Azure service tag Internet, or the literal "*".
// A narrower CIDR is a scoped source (external but not the whole internet) and is
// not treated as internet exposure here.
func internetSource(src string) bool {
	s := strings.TrimSpace(src)
	switch s {
	case "*", "Internet", "internet":
		return true
	}
	return netmatch.IsDefaultRoute(s)
}

// anyInternetSource reports whether any of the sources admits the internet.
func anyInternetSource(sources []string) bool {
	for _, s := range sources {
		if internetSource(s) {
			return true
		}
	}
	return false
}

// --- AWS security groups (ingress, allow-only, unordered) ---

type awsSGRule struct {
	Protocol string `json:"protocol"`
	FromPort int    `json:"from_port"`
	ToPort   int    `json:"to_port"`
	CIDR     string `json:"cidr"`
	IPv6CIDR string `json:"ipv6_cidr"`
}

// parseAWSSecurityGroupIngress parses a security group's ingress_rules fact. AWS
// security-group rules are allow-only and stateful, and any matching rule permits
// the traffic (no order), so every rule is an unordered allow (verified against the
// EC2 security-group semantics: rules are permissive, evaluated as a set).
func parseAWSSecurityGroupIngress(ingressJSON string) []netRule {
	var raw []awsSGRule
	if json.Unmarshal([]byte(ingressJSON), &raw) != nil {
		return nil
	}
	var out []netRule
	for _, r := range raw {
		out = append(out, netRule{
			allow:       true,
			internetSrc: internetSource(r.CIDR) || internetSource(r.IPv6CIDR),
			proto:       awsProto(r.Protocol),
			allPorts:    r.Protocol == "-1" || (r.FromPort == 0 && r.ToPort == 0 && r.Protocol == "-1"),
			fromPort:    r.FromPort,
			toPort:      r.ToPort,
		})
	}
	return out
}

// awsProto normalizes an AWS protocol token to a canonical name. Security groups
// use names ("tcp"), network ACLs use IANA numbers ("6"); both are reconciled here
// so a security-group rule and a network-ACL entry intersect on the same protocol.
// "-1" means every protocol.
func awsProto(p string) string {
	switch strings.ToLower(p) {
	case "-1", "all":
		return "all"
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	}
	return strings.ToLower(p)
}

// --- AWS network ACLs (ordered allow/deny, first match by rule_number) ---

type awsNaclEntry struct {
	RuleNumber int    `json:"rule_number"`
	Egress     bool   `json:"egress"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	IPv6CIDR   string `json:"ipv6_cidr"`
	FromPort   int    `json:"from_port"`
	ToPort     int    `json:"to_port"`
}

// parseAWSNaclIngress parses a network ACL's entries fact into ordered ingress
// rules. Network ACLs are stateless and evaluated in ascending rule-number order,
// first match wins (verified against the VPC network-ACL semantics); only ingress
// (non-egress) entries gate inbound internet traffic.
func parseAWSNaclIngress(entriesJSON string) []netRule {
	var raw []awsNaclEntry
	if json.Unmarshal([]byte(entriesJSON), &raw) != nil {
		return nil
	}
	var out []netRule
	for _, e := range raw {
		if e.Egress {
			continue
		}
		out = append(out, netRule{
			allow:       strings.EqualFold(e.Action, "allow"),
			internetSrc: internetSource(e.CIDR) || internetSource(e.IPv6CIDR),
			proto:       awsProto(e.Protocol),
			allPorts:    e.Protocol == "-1" || (e.FromPort == 0 && e.ToPort == 0),
			fromPort:    e.FromPort,
			toPort:      e.ToPort,
			order:       e.RuleNumber,
			ordered:     true,
		})
	}
	return out
}

// --- Azure NSG (ordered allow/deny by priority) ---

type azureNSGRule struct {
	Priority         int      `json:"priority"`
	Direction        string   `json:"direction"`
	Access           string   `json:"access"`
	Protocol         string   `json:"protocol"`
	SourcePrefixes   []string `json:"source_prefixes"`
	DestinationPorts []string `json:"destination_ports"`
}

// parseAzureNSGInbound parses an NSG's security_rules fact into ordered inbound
// rules. Azure NSG rules are evaluated by ascending priority, first match wins,
// with an explicit Allow/Deny access (verified against the NSG evaluation
// semantics); only Inbound rules gate inbound internet traffic.
func parseAzureNSGInbound(rulesJSON string) []netRule {
	var raw []azureNSGRule
	if json.Unmarshal([]byte(rulesJSON), &raw) != nil {
		return nil
	}
	var out []netRule
	for _, r := range raw {
		if !strings.EqualFold(r.Direction, "Inbound") {
			continue
		}
		from, to, all := azurePortSpan(r.DestinationPorts)
		out = append(out, netRule{
			allow:       strings.EqualFold(r.Access, "Allow"),
			internetSrc: anyInternetSource(r.SourcePrefixes),
			proto:       azureProto(r.Protocol),
			allPorts:    all,
			fromPort:    from,
			toPort:      to,
			order:       r.Priority,
			ordered:     true,
		})
	}
	return out
}

func azureProto(p string) string {
	if p == "*" {
		return "all"
	}
	return strings.ToLower(p)
}

// azurePortSpan reduces an NSG destination-ports list to a span. "*" or a range
// is handled; multiple discrete ports collapse to their covering span (a
// conservative over-approximation the trace records), and "*" means all.
func azurePortSpan(ports []string) (from, to int, all bool) {
	if len(ports) == 0 {
		return 0, 0, true
	}
	lo, hi := 65536, -1
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "*" {
			return 0, 0, true
		}
		a, b := p, p
		if i := strings.Index(p, "-"); i >= 0 {
			a, b = p[:i], p[i+1:]
		}
		ai, e1 := strconv.Atoi(a)
		bi, e2 := strconv.Atoi(b)
		if e1 != nil || e2 != nil {
			continue
		}
		if ai < lo {
			lo = ai
		}
		if bi > hi {
			hi = bi
		}
	}
	if hi < 0 {
		return 0, 0, true
	}
	return lo, hi, false
}

// --- GCP firewalls (ordered allow/deny by priority) ---

type gcpProtoFact struct {
	Protocol string   `json:"protocol"`
	Ports    []string `json:"ports"`
}

// parseGCPFirewall parses a GCP firewall node's allowed_rules / denied_rules and
// scoping facts into ordered ingress rules. GCP firewall rules are evaluated by
// ascending priority, first match wins; allow vs deny is which of allowed/denied
// is populated (verified against the VPC firewall semantics). Only INGRESS rules
// gate inbound internet traffic.
func parseGCPFirewall(allowedJSON, deniedJSON, direction, sourceRanges string, priority int) []netRule {
	if direction != "" && !strings.EqualFold(direction, "INGRESS") {
		return nil
	}
	internet := false
	for _, s := range strings.Split(sourceRanges, ",") {
		if internetSource(s) {
			internet = true
		}
	}
	parse := func(js string, allow bool) []netRule {
		var raw []gcpProtoFact
		if js == "" || json.Unmarshal([]byte(js), &raw) != nil {
			return nil
		}
		var rs []netRule
		for _, p := range raw {
			from, to, all := gcpPortSpan(p.Ports)
			rs = append(rs, netRule{
				allow:       allow,
				internetSrc: internet,
				proto:       gcpProto(p.Protocol),
				allPorts:    all,
				fromPort:    from,
				toPort:      to,
				order:       priority,
				ordered:     true,
			})
		}
		return rs
	}
	out := parse(allowedJSON, true)
	out = append(out, parse(deniedJSON, false)...)
	return out
}

func gcpProto(p string) string { return strings.ToLower(p) }

func gcpPortSpan(ports []string) (from, to int, all bool) {
	if len(ports) == 0 {
		return 0, 0, true // no ports listed means all ports for the protocol
	}
	return azurePortSpan(ports) // same "N" or "N-M" form
}

// internetOpenPorts returns the protocol/port spans an internet source can reach
// given a resource's applicable rules. Unordered AWS security-group rules are a
// permissive union of internet allows. Ordered rules (NACL, NSG, GCP) are sorted
// ascending and evaluated first-match: an internet allow contributes a span only
// if no earlier internet-matching rule denies it. The result is sorted and
// deterministic.
func internetOpenPorts(rules []netRule) []portSpan {
	var unordered, ordered []netRule
	for _, r := range rules {
		if r.ordered {
			ordered = append(ordered, r)
		} else {
			unordered = append(unordered, r)
		}
	}
	spans := map[portSpan]bool{}

	// Unordered allow-union (AWS security groups): any internet allow opens its span.
	for _, r := range unordered {
		if r.allow && r.internetSrc {
			spans[spanOf(r)] = true
		}
	}
	// Ordered first-match (NACL / NSG / GCP): the first internet-matching rule for a
	// span decides it. Sort by order, then walk; a deny seen first blocks the span.
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].order < ordered[j].order })
	decided := map[portSpan]bool{}
	for _, r := range ordered {
		if !r.internetSrc {
			continue
		}
		s := spanOf(r)
		if decided[s] {
			continue
		}
		decided[s] = true
		if r.allow {
			spans[s] = true
		}
	}

	out := make([]portSpan, 0, len(spans))
	for s := range spans {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func spanOf(r netRule) portSpan {
	return portSpan{Proto: r.proto, AllPorts: r.allPorts, From: r.fromPort, To: r.toPort}
}
