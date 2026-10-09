package netmatch

import "testing"

func TestIsDefaultRoute(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0/0":     true,
		"::/0":          true,
		"0.0.0.0/1":     false, // half the internet is not the default route
		"10.0.0.0/8":    false,
		"1.2.3.4/32":    false,
		"2001:db8::/32": false,
		"not-a-cidr":    false,
		"":              false,
	}
	for in, want := range cases {
		if got := IsDefaultRoute(in); got != want {
			t.Errorf("IsDefaultRoute(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPrefixContains(t *testing.T) {
	cases := []struct {
		outer, inner string
		want         bool
	}{
		{"0.0.0.0/0", "10.0.0.0/8", true},
		{"10.0.0.0/8", "10.1.0.0/16", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},   // equal contains itself
		{"10.0.0.0/8", "11.0.0.0/8", false},  // disjoint
		{"10.0.0.0/16", "10.0.0.0/8", false}, // a more specific outer cannot contain a broader inner
		{"0.0.0.0/0", "::/0", false},         // cross-family never contains
		{"::/0", "2001:db8::/32", true},
		{"2001:db8::/32", "2001:db8:1::/48", true},
		{"bad", "10.0.0.0/8", false},
		{"10.0.0.0/8", "bad", false},
	}
	for _, c := range cases {
		if got := PrefixContains(c.outer, c.inner); got != c.want {
			t.Errorf("PrefixContains(%q,%q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}

func TestPrefixContainsAddr(t *testing.T) {
	cases := []struct {
		cidr, ip string
		want     bool
	}{
		{"0.0.0.0/0", "8.8.8.8", true},
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "8.8.8.8", false},
		{"::/0", "2001:db8::1", true},
		{"10.0.0.0/8", "notanip", false},
	}
	for _, c := range cases {
		if got := PrefixContainsAddr(c.cidr, c.ip); got != c.want {
			t.Errorf("PrefixContainsAddr(%q,%q) = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}
