package fsperm

import "testing"

// Security descriptors modelled on real Windows 11 folders (read with Get-Acl
// on 2026-09-11), with synthetic account and capability SIDs.
const (
	trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	capabilitySID    = "S-1-15-3-1111111111-2222222222-3333333333-4444444444"
	otherLocalUser   = "S-1-5-21-1-2-3-1003"
)

func TestRealWindowsLayouts(t *testing.T) {
	tests := []struct {
		name      string
		sddl      string
		describe  string
		inherited string
		replace   bool
	}{
		{
			// Owned by TrustedInstaller; Authenticated Users may only create
			// folders on the root itself and get modify on what they create.
			name: `C:\`,
			sddl: "O:" + trustedInstaller + "G:" + trustedInstaller +
				"D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;" + capabilitySID + ")",
			describe:  "Authenticated Users (write); Users (read)",
			inherited: "Authenticated Users (read, write); Users (read)",
			replace:   false,
		},
		{
			name:      `C:\Users`,
			sddl:      "O:SYG:SYD:PAI(A;OICIIO;GXGR;;;WD)(A;;0x1200a9;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)",
			describe:  "Everyone (read); Users (read)",
			inherited: "Everyone (read); Users (read)",
		},
		{
			// %LOCALAPPDATA%: full control for an AppContainer capability,
			// which is not an account.
			name: `%LOCALAPPDATA%`,
			sddl: "O:" + user + "G:S-1-5-21-1-2-3-513D:AI(A;ID;FA;;;" + capabilitySID + ")(A;OICIIOID;GA;;;" + capabilitySID +
				")(A;OICIID;FA;;;" + user + ")(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)",
			describe:  "none",
			inherited: "none",
		},
		{
			// A %TEMP% where another local account was granted modify.
			name:      `%TEMP% shared with another account`,
			sddl:      "O:" + user + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")(A;OICI;0x1301bf;;;" + otherLocalUser + ")",
			describe:  otherLocalUser + " (read, write)",
			inherited: otherLocalUser + " (read, write)",
			replace:   true,
		},
	}
	for _, tt := range tests {
		rep, err := evaluateSDDL(tt.name, tt.sddl, user, staticResolver)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got := rep.Describe(); got != tt.describe {
			t.Errorf("%s: Describe() = %q, want %q", tt.name, got, tt.describe)
		}
		if got := rep.DescribeInherited(); got != tt.inherited {
			t.Errorf("%s: DescribeInherited() = %q, want %q", tt.name, got, tt.inherited)
		}
		if rep.OthersCanReplace() != tt.replace {
			t.Errorf("%s: OthersCanReplace() = %v, want %v", tt.name, rep.OthersCanReplace(), tt.replace)
		}
	}
}
