package fsperm

import (
	"sort"
	"strings"
	"testing"
)

const user = "S-1-5-21-1-2-3-1001"

func TestEvaluateSDDL(t *testing.T) {
	tests := []struct {
		name string
		sddl string
		want string // Describe() output
	}{
		{
			name: "user profile: owner, SYSTEM, Administrators only",
			sddl: "O:" + user + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")",
			want: "none",
		},
		{
			name: "folder created under a drive root inherits Authenticated Users modify",
			sddl: "O:" + user + "D:AI(A;ID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1301bf;;;AU)(A;OICIID;0x1200a9;;;BU)(A;OICIIOID;SDGXGWGR;;;AU)",
			want: "Authenticated Users (read, write); Users (read)",
		},
		{
			name: "Everyone full control",
			sddl: "O:BAD:P(A;;FA;;;WD)",
			want: "Everyone (read, write)",
		},
		{
			name: "NULL DACL grants everyone everything",
			sddl: "O:BAD:NO_ACCESS_CONTROL",
			want: "Everyone (no DACL) (read, write)",
		},
		{
			name: "another account owns the entry",
			sddl: "O:S-1-5-21-9-9-9-500D:P(A;;FA;;;" + user + ")",
			want: "S-1-5-21-9-9-9-500 (owner) (write)",
		},
		{
			name: "SYSTEM as owner is trusted",
			sddl: "O:SYD:P(A;;FA;;;" + user + ")",
			want: "none",
		},
		{
			name: "execute-only grants no data access",
			sddl: "O:BAD:P(A;;FX;;;BU)",
			want: "none",
		},
		{
			name: "WRITE_DAC alone is write exposure",
			sddl: "O:BAD:P(A;;WD;;;BU)",
			want: "Users (write)",
		},
		{
			name: "deny entries are ignored conservatively",
			sddl: "O:BAD:P(D;;FA;;;WD)(A;;FR;;;WD)",
			want: "Everyone (read)",
		},
		{
			name: "group section is accepted",
			sddl: "O:" + user + "G:S-1-5-21-1-2-3-513D:P(A;;FA;;;" + user + ")",
			want: "none",
		},
		{
			name: "Owner Rights inherits the owner's trust",
			sddl: "O:" + user + "D:P(A;;FA;;;OW)",
			want: "none",
		},
		{
			name: "Owner Rights with a foreign owner is exposure",
			sddl: "O:S-1-5-21-9-9-9-500D:P(A;;FA;;;OW)",
			want: "Owner Rights (read, write); S-1-5-21-9-9-9-500 (owner) (write)",
		},
		{
			name: "well-known SID written out in full",
			sddl: "O:BAD:P(A;;GR;;;S-1-1-0)",
			want: "Everyone (read)",
		},
		{
			name: "decimal access mask",
			sddl: "O:BAD:P(A;;2;;;BU)",
			want: "Users (write)",
		},
		{
			name: "trailing SACL section is ignored",
			sddl: "O:BAD:P(A;;FA;;;SY)S:AI(AU;SAFA;FA;;;WD)",
			want: "none",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := evaluateSDDL("x", tt.sddl, user, staticResolver)
			if err != nil {
				t.Fatal(err)
			}
			if got := rep.Describe(); got != tt.want {
				t.Errorf("Describe() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEvaluateSDDLRejectsWhatItCannotEvaluate(t *testing.T) {
	for _, sddl := range []string{
		"",
		"garbage",
		"O:BA",                         // no DACL section
		"O:BAD:P(A;;ZZ;;;WD)",          // unknown right
		"O:BAD:P(Q;;FA;;;WD)",          // unknown ACE type
		"O:BAD:P(A;;FA)",               // too few fields
		"O:BAD:P(A;;FA;;;WD",           // unterminated
		"O:BAD:Pjunk",                  // trailing garbage
		"O:BAD:P(A;;0xZZ;;;WD)",        // bad hex
		"O:BAD:P(A;;F;;;WD)",           // odd-length rights
		"O:BAD:P(A;;99999999999;;;WD)", // out of range
		"O:BAD:P(A;;FA;;;)",            // empty trustee (found by fuzzing)
		"O:BAD:P(A;;FA;;;not a sid)",   // malformed trustee
		"O:BAD:P(A;;FA;;;S-1-)",        // truncated SID
	} {
		if rep, err := evaluateSDDL("x", sddl, user, staticResolver); err == nil {
			t.Errorf("evaluateSDDL(%q) accepted: %+v", sddl, rep)
		}
	}
}

func TestReportPredicates(t *testing.T) {
	rep, err := evaluateSDDL("x", "O:BAD:P(A;;FR;;;BU)", user, staticResolver)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OthersCanRead() || rep.OthersCanWrite() {
		t.Errorf("read-only exposure misclassified: %+v", rep)
	}
	if rep.Owner != "Administrators" {
		t.Errorf("Owner = %q", rep.Owner)
	}
	private, _ := evaluateSDDL("x", "O:BAD:P(A;;FA;;;"+user+")", user, staticResolver)
	if private.OthersCanRead() || private.OthersCanWrite() || private.Describe() != "none" {
		t.Errorf("private entry reported exposure: %+v", private)
	}
}

func FuzzEvaluateSDDL(f *testing.F) {
	f.Add("O:" + user + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user + ")")
	f.Add("O:BAD:AI(A;OICIID;0x1301bf;;;AU)")
	f.Add("O:BAD:NO_ACCESS_CONTROL")
	f.Add("O:BAD:P(D;;FA;;;WD)(A;;FR;;;WD)S:")
	f.Fuzz(func(t *testing.T, sddl string) {
		rep, err := evaluateSDDL("x", sddl, user, staticResolver)
		if err != nil {
			return
		}
		if !sort.SliceIsSorted(rep.Exposures, func(i, j int) bool { return rep.Exposures[i].Principal < rep.Exposures[j].Principal }) {
			t.Fatalf("exposures not sorted: %+v", rep.Exposures)
		}
		for _, e := range rep.Exposures {
			// The current user is trusted and must never appear as an exposure.
			// Compare exactly: a different SID can share the user's prefix.
			self := strings.TrimSuffix(e.Principal, " (owner)") == user
			if e.Principal == "" || (!e.Read && !e.Write) || self {
				t.Fatalf("invalid exposure %+v for %q", e, sddl)
			}
		}
	})
}
