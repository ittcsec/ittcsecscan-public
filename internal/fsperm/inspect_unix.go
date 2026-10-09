//go:build unix

package fsperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

func inspect(path string) (Report, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Report{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Report{}, fmt.Errorf("%s: no ownership information: %w", path, errors.ErrUnsupported)
	}
	owner, gid := uint64(st.Uid), uint64(st.Gid)
	rep := Report{Path: path, Owner: "uid " + strconv.FormatUint(owner, 10)}
	set, inherited := exposureSet{}, exposureSet{}

	euid := os.Geteuid()
	self := func(uid uint64) bool { return uid == 0 || (euid >= 0 && uid == uint64(euid)) }
	if !self(owner) {
		// The owner can always change the mode, and so everything else.
		set.add(rep.Owner+" (owner)", false, true, true)
	}

	// In a sticky directory only an entry's owner (or the directory's owner)
	// may delete or rename it, so write access there does not allow replacing
	// someone else's entries.
	sticky := fi.Mode()&fs.ModeSticky != 0
	access, deflt, incomplete, err := extendedACLs(path, fi.IsDir())
	if err != nil {
		return Report{}, err
	}
	if access != nil {
		entries, err := parsePOSIXACL(access)
		if err != nil {
			return Report{}, fmt.Errorf("%s: access ACL: %w", path, err)
		}
		addPOSIXACL(set, entries, self, gid, sticky)
	} else {
		perm := fi.Mode().Perm()
		gw, ow := perm&0o020 != 0, perm&0o002 != 0
		set.add(groupLabel(gid), perm&0o040 != 0, gw, gw && !sticky)
		set.add("others", perm&0o004 != 0, ow, ow && !sticky)
	}
	if deflt != nil {
		entries, err := parsePOSIXACL(deflt)
		if err != nil {
			return Report{}, fmt.Errorf("%s: default ACL: %w", path, err)
		}
		addPOSIXACL(inherited, entries, self, gid, true)
	}
	rep.Exposures, rep.Inherited, rep.Incomplete = set.sorted(), inherited.sorted(), incomplete
	return rep, nil
}
