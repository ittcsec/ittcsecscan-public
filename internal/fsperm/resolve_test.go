package fsperm

import "testing"

// GitHub's Windows runners run as the built-in Administrator account, and
// Windows writes that account's SID as the machine-relative alias "LA" in
// SDDL. CI caught the evaluator reporting the current user as an exposure
// because it could not resolve "LA". These cases pin the fix.
func TestRelativeAliasResolvesToCurrentUser(t *testing.T) {
	const machineAdmin = "S-1-5-21-7-8-9-500"
	resolve := func(trustee string) string {
		if trustee == "LA" {
			return machineAdmin
		}
		return staticResolver(trustee)
	}

	rep, err := evaluateSDDL("x", "O:LAD:P(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", machineAdmin, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Describe() != "none" {
		t.Errorf("current user written as LA reported as exposure: %s", rep.Describe())
	}

	// The same descriptor evaluated for a different user must still report
	// the Administrator account's access, with a readable name.
	rep, err = evaluateSDDL("x", "O:LAD:P(A;OICI;FA;;;LA)", "S-1-5-21-7-8-9-1001", resolve)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rep.Describe(), "local Administrator account (read, write); local Administrator account (owner) (write)"; got != want {
		t.Errorf("Describe() = %q, want %q", got, want)
	}
}

func TestUnresolvedAliasIsNeverTrusted(t *testing.T) {
	rep, err := evaluateSDDL("x", "O:BAD:P(A;;FA;;;DU)", "S-1-5-21-7-8-9-1001", staticResolver)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Describe(); got != "Domain Users (read, write)" {
		t.Errorf("Describe() = %q", got)
	}
}
