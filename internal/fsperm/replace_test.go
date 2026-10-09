package fsperm

import (
	"encoding/binary"
	"testing"
)

func exposureOf(t *testing.T, rep Report, principal string) Exposure {
	t.Helper()
	for _, e := range rep.Exposures {
		if e.Principal == principal {
			return e
		}
	}
	return Exposure{}
}

func TestSDDLReplaceRights(t *testing.T) {
	tests := []struct {
		name    string
		ace     string
		write   bool
		replace bool
	}{
		// C:\ grants Authenticated Users "create folders" on the drive root
		// itself: they can add entries but not remove or rename existing ones.
		{"drive root create-folders only", "(A;;LC;;;AU)", true, false},
		{"delete child", "(A;;DT;;;AU)", true, true},
		{"modify includes DELETE", "(A;;0x1301bf;;;AU)", true, true},
		{"generic write excludes delete", "(A;;GW;;;AU)", true, false},
		{"write DAC can grant anything", "(A;;WD;;;AU)", true, true},
		{"read only", "(A;;FR;;;AU)", false, false},
	}
	for _, tt := range tests {
		rep, err := evaluateSDDL("x", "O:BAD:P"+tt.ace, user, staticResolver)
		if err != nil {
			t.Fatal(err)
		}
		e := exposureOf(t, rep, "Authenticated Users")
		if e.Write != tt.write || e.Replace != tt.replace || rep.OthersCanReplace() != tt.replace {
			t.Errorf("%s: write=%v replace=%v, want write=%v replace=%v", tt.name, e.Write, e.Replace, tt.write, tt.replace)
		}
	}
	rep, _ := evaluateSDDL("x", "O:S-1-5-21-9-9-9-500D:P(A;;FA;;;"+user+")", user, staticResolver)
	if !rep.OthersCanReplace() || rep.DescribeReplace() != "S-1-5-21-9-9-9-500 (owner)" {
		t.Errorf("foreign owner must be able to replace: %+v", rep)
	}
}

func TestSDDLInheritedAccess(t *testing.T) {
	// The inherit-only entries C:\ gives new subfolders, plus Creator Owner.
	sddl := "O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICIIO;SDGXGWGR;;;AU)(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)"
	rep, err := evaluateSDDL("x", sddl, user, staticResolver)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Describe() != "none" {
		t.Errorf("inherit-only entries counted as direct access: %s", rep.Describe())
	}
	if got := rep.DescribeInherited(); got != "Authenticated Users (read, write)" {
		t.Errorf("DescribeInherited() = %q", got)
	}

	rep, _ = evaluateSDDL("x", "O:BAD:P(A;OICI;FR;;;BU)", user, staticResolver)
	if rep.Describe() != "Users (read)" || rep.DescribeInherited() != "Users (read)" {
		t.Errorf("an inheritable entry applies to the entry and its children: %+v", rep)
	}
}

// acl builds a Linux POSIX ACL xattr value.
func acl(entries ...aclEntry) []byte {
	b := make([]byte, 4, 4+8*len(entries))
	binary.LittleEndian.PutUint32(b, posixACLVersion)
	for _, e := range entries {
		var rec [8]byte
		binary.LittleEndian.PutUint16(rec[0:], e.tag)
		binary.LittleEndian.PutUint16(rec[2:], e.perm)
		binary.LittleEndian.PutUint32(rec[4:], e.id)
		b = append(b, rec[:]...)
	}
	return b
}

func TestPOSIXACL(t *testing.T) {
	self := func(uid uint64) bool { return uid == 0 || uid == 1000 }
	tests := []struct {
		name    string
		entries []aclEntry
		sticky  bool
		want    string
		replace bool
	}{
		{
			name:    "named user with read-write, masked to read-write",
			entries: []aclEntry{{aclUserObj, 7, 0}, {aclUser, 6, 1002}, {aclGroupObj, 0, 0}, {aclMask, 6, 0}, {aclOther, 0, 0}},
			want:    "user uid 1002 (read, write)",
			replace: true,
		},
		{
			name:    "mask limits named entries",
			entries: []aclEntry{{aclUserObj, 7, 0}, {aclUser, 7, 1002}, {aclGroup, 7, 2000}, {aclGroupObj, 5, 0}, {aclMask, 4, 0}, {aclOther, 0, 0}},
			want:    "group gid 100 (read); group gid 2000 (read); user uid 1002 (read)",
		},
		{
			name:    "the current user and root are trusted",
			entries: []aclEntry{{aclUserObj, 7, 0}, {aclUser, 7, 1000}, {aclUser, 7, 0}, {aclGroupObj, 0, 0}, {aclMask, 7, 0}, {aclOther, 0, 0}},
			want:    "none",
		},
		{
			name:    "other is not masked; sticky blocks replace",
			entries: []aclEntry{{aclUserObj, 7, 0}, {aclGroupObj, 0, 0}, {aclMask, 0, 0}, {aclOther, 7, 0}},
			sticky:  true,
			want:    "others (read, write)",
		},
	}
	for _, tt := range tests {
		entries, err := parsePOSIXACL(acl(tt.entries...))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		set := exposureSet{}
		addPOSIXACL(set, entries, self, 100, tt.sticky)
		rep := Report{Exposures: set.sorted()}
		if rep.Describe() != tt.want || rep.OthersCanReplace() != tt.replace {
			t.Errorf("%s: %q replace=%v, want %q replace=%v", tt.name, rep.Describe(), rep.OthersCanReplace(), tt.want, tt.replace)
		}
	}
}

func TestPOSIXACLRejectsMalformed(t *testing.T) {
	bad := [][]byte{
		nil,
		{2, 0, 0},
		acl()[:4], // no entries
		append(acl(aclEntry{aclUserObj, 7, 0}), 0),                                   // trailing byte
		func() []byte { b := acl(aclEntry{aclUserObj, 7, 0}); b[0] = 1; return b }(), // version 1
		acl(aclEntry{0x40, 7, 0}),                                                    // unknown tag
		acl(aclEntry{aclUser, 8, 5}),                                                 // permissions out of range
	}
	for i, b := range bad {
		if _, err := parsePOSIXACL(b); err == nil {
			t.Errorf("case %d accepted: %v", i, b)
		}
	}
}

func FuzzParsePOSIXACL(f *testing.F) {
	f.Add(acl(aclEntry{aclUserObj, 7, 0}, aclEntry{aclUser, 6, 1002}, aclEntry{aclMask, 6, 0}, aclEntry{aclOther, 0, 0}))
	f.Add([]byte{2, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		entries, err := parsePOSIXACL(b)
		if err != nil {
			return
		}
		set := exposureSet{}
		addPOSIXACL(set, entries, func(uint64) bool { return false }, 1, false)
		for _, e := range set.sorted() {
			if e.Replace && !e.Write {
				t.Fatalf("replace without write: %+v", e)
			}
		}
	})
}
