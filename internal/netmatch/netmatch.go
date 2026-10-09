// Package netmatch is the project's CIDR and IPv6 matcher: pure address and
// prefix parsing and comparison over net/netip, with no network I/O. It is a
// shared leaf utility (ADR-0024 §6, closing ADR-0021 DE-3) used by the reachability
// engine (internal/graph) and adoptable by the detection engine (internal/rules);
// keeping it in its own package lets those gated packages consume CIDR matching
// without importing net/netip directly.
package netmatch

import "net/netip"

// This is the project's real CIDR / IPv6 matcher (ADR-0024 §6), closing the
// deferred cidr operator of ADR-0021 DE-3. It parses with net/netip, which is
// deterministic and allocation-light and is NOT the forbidden net package (the
// AST determinism gate matches exact import paths, so it permits net/netip; the
// depguard deterministic-graph rule-set carries a net/netip allow-exception).
// Nothing here touches the network; a prefix string is only parsed and compared.

// IsDefaultRoute reports whether a CIDR string is the whole internet: the IPv4
// default route 0.0.0.0/0 or the IPv6 default route ::/0. This is the clear
// internet-source signal a firewall rule carries (ADR-0024 §3); a narrower public
// prefix is a scoped exposure, handled by the engine, not "the internet".
func IsDefaultRoute(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return p.Bits() == 0
}

// PrefixContains reports whether the outer CIDR fully contains the inner CIDR:
// same address family, outer no more specific than inner, and outer covers
// inner's network address. It is the cidr_contains predicate: for example
// 0.0.0.0/0 contains 10.0.0.0/8, and 10.0.0.0/8 contains 10.1.0.0/16, but
// 10.0.0.0/8 does not contain 11.0.0.0/8 and an IPv4 prefix never contains an
// IPv6 one. A malformed prefix yields false, never a panic.
func PrefixContains(outer, inner string) bool {
	o, err1 := netip.ParsePrefix(outer)
	i, err2 := netip.ParsePrefix(inner)
	if err1 != nil || err2 != nil {
		return false
	}
	o = o.Masked()
	i = i.Masked()
	if o.Addr().Is4() != i.Addr().Is4() {
		return false // different address families never contain one another
	}
	if o.Bits() > i.Bits() {
		return false // a more specific outer cannot contain a broader inner
	}
	return o.Contains(i.Addr())
}

// PrefixContainsAddr reports whether a CIDR contains a single IP address. A
// malformed prefix or address yields false.
func PrefixContainsAddr(cidr, ip string) bool {
	p, err1 := netip.ParsePrefix(cidr)
	a, err2 := netip.ParseAddr(ip)
	if err1 != nil || err2 != nil {
		return false
	}
	return p.Contains(a)
}
