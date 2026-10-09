package graph

import "testing"

func hasSpan(spans []portSpan, proto string, from, to int) bool {
	for _, s := range spans {
		if s.Proto == proto && s.From == from && s.To == to {
			return true
		}
	}
	return false
}

func TestInternetSource(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "::/0", "*", "Internet"} {
		if !internetSource(s) {
			t.Errorf("internetSource(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"10.0.0.0/8", "1.2.3.4/32", "VirtualNetwork", "203.0.113.0/24"} {
		if internetSource(s) {
			t.Errorf("internetSource(%q) = true, want false", s)
		}
	}
}

// TestAWSSecurityGroupOpenVsScoped proves an SG ingress rule from 0.0.0.0/0 opens
// its port and a scoped-CIDR rule does not.
func TestAWSSecurityGroupOpenVsScoped(t *testing.T) {
	open := parseAWSSecurityGroupIngress(`[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"0.0.0.0/0"}]`)
	if got := internetOpenPorts(open); !hasSpan(got, "tcp", 22, 22) {
		t.Errorf("0.0.0.0/0:22 not open: %+v", got)
	}
	scoped := parseAWSSecurityGroupIngress(`[{"protocol":"tcp","from_port":22,"to_port":22,"cidr":"203.0.113.0/24"}]`)
	if got := internetOpenPorts(scoped); len(got) != 0 {
		t.Errorf("scoped-CIDR rule wrongly open: %+v", got)
	}
}

// TestAWSNaclDenyOverridesOpen is the ordered-first-match proof for AWS: a lower
// rule-number NACL deny of an internet source blocks the port even though a
// higher-numbered entry allows it.
func TestAWSNaclDenyOverridesOpen(t *testing.T) {
	entries := `[
		{"rule_number":100,"egress":false,"protocol":"6","action":"deny","cidr":"0.0.0.0/0","from_port":22,"to_port":22},
		{"rule_number":200,"egress":false,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22}]`
	rules := parseAWSNaclIngress(entries)
	if got := internetOpenPorts(rules); len(got) != 0 {
		t.Errorf("lower-numbered NACL deny did not override the allow: %+v", got)
	}
	// Reversed order: allow at 100 wins.
	entries2 := `[
		{"rule_number":100,"egress":false,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},
		{"rule_number":200,"egress":false,"protocol":"6","action":"deny","cidr":"0.0.0.0/0","from_port":22,"to_port":22}]`
	if got := internetOpenPorts(parseAWSNaclIngress(entries2)); !hasSpan(got, "tcp", 22, 22) {
		t.Errorf("lower-numbered NACL allow should win: %+v", got)
	}
}

// TestAzureNSGPriorityDeny is the priority-first-match proof for Azure: a
// lower-priority-number (higher-priority) Deny beats a higher-number Allow.
func TestAzureNSGPriorityDeny(t *testing.T) {
	rules := `[
		{"priority":100,"direction":"Inbound","access":"Deny","protocol":"Tcp","source_prefixes":["Internet"],"destination_ports":["3389"]},
		{"priority":200,"direction":"Inbound","access":"Allow","protocol":"Tcp","source_prefixes":["*"],"destination_ports":["3389"]}]`
	if got := internetOpenPorts(parseAzureNSGInbound(rules)); len(got) != 0 {
		t.Errorf("higher-priority NSG deny did not win: %+v", got)
	}
	allow := `[{"priority":100,"direction":"Inbound","access":"Allow","protocol":"Tcp","source_prefixes":["0.0.0.0/0"],"destination_ports":["443"]}]`
	if got := internetOpenPorts(parseAzureNSGInbound(allow)); !hasSpan(got, "tcp", 443, 443) {
		t.Errorf("NSG internet allow on 443 not open: %+v", got)
	}
}

// TestGCPFirewallAllowDeny proves GCP allow/deny by populated key and priority.
func TestGCPFirewallAllowDeny(t *testing.T) {
	openRules := parseGCPFirewall(`[{"protocol":"tcp","ports":["22"]}]`, "", "INGRESS", "0.0.0.0/0", 1000)
	if got := internetOpenPorts(openRules); !hasSpan(got, "tcp", 22, 22) {
		t.Errorf("GCP ingress allow 0.0.0.0/0:22 not open: %+v", got)
	}
	// A higher-priority (lower number) deny blocks it.
	deny := parseGCPFirewall("", `[{"protocol":"tcp","ports":["22"]}]`, "INGRESS", "0.0.0.0/0", 100)
	all := append(openRules, deny...)
	if got := internetOpenPorts(all); len(got) != 0 {
		t.Errorf("higher-priority GCP deny did not override the allow: %+v", got)
	}
	// Egress firewall is not inbound exposure.
	if got := parseGCPFirewall(`[{"protocol":"tcp","ports":["22"]}]`, "", "EGRESS", "0.0.0.0/0", 1000); got != nil {
		t.Errorf("egress firewall wrongly parsed as inbound: %+v", got)
	}
}
