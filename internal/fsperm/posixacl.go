package fsperm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// Linux POSIX ACL extended-attribute format (linux/posix_acl_xattr.h): a
// little-endian 4-byte version (2) followed by 8-byte entries of tag (u16),
// permissions (u16), and id (u32).
const (
	posixACLVersion = 2

	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20

	aclRead  = 0x4
	aclWrite = 0x2
)

type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

func parsePOSIXACL(b []byte) ([]aclEntry, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("malformed ACL of %d bytes", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != posixACLVersion {
		return nil, fmt.Errorf("unsupported ACL version %d", v)
	}
	entries := make([]aclEntry, 0, (len(b)-4)/8)
	for i := 4; i < len(b); i += 8 {
		e := aclEntry{
			tag:  binary.LittleEndian.Uint16(b[i:]),
			perm: binary.LittleEndian.Uint16(b[i+2:]),
			id:   binary.LittleEndian.Uint32(b[i+4:]),
		}
		switch e.tag {
		case aclUserObj, aclUser, aclGroupObj, aclGroup, aclMask, aclOther:
		default:
			return nil, fmt.Errorf("unknown ACL tag %#x", e.tag)
		}
		if e.perm > 7 {
			return nil, fmt.Errorf("invalid ACL permissions %#o", e.perm)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, errors.New("empty ACL")
	}
	return entries, nil
}

// addPOSIXACL records the exposures an ACL grants. Named users and groups and
// the owning group are limited by the mask entry; the owner entry is handled
// by the caller's owner check. self reports trusted user IDs; gid is the
// entry's owning group.
func addPOSIXACL(set exposureSet, entries []aclEntry, self func(uint64) bool, gid uint64, sticky bool) {
	mask := uint16(7)
	for _, e := range entries {
		if e.tag == aclMask {
			mask = e.perm
		}
	}
	add := func(label string, p uint16) {
		r, w := p&aclRead != 0, p&aclWrite != 0
		set.add(label, r, w, w && !sticky)
	}
	for _, e := range entries {
		switch e.tag {
		case aclUser:
			if self(uint64(e.id)) {
				continue
			}
			add("user uid "+strconv.FormatUint(uint64(e.id), 10), e.perm&mask)
		case aclGroupObj:
			add(groupLabel(gid), e.perm&mask)
		case aclGroup:
			add(groupLabel(uint64(e.id)), e.perm&mask)
		case aclOther:
			add("others", e.perm)
		}
	}
}

func groupLabel(gid uint64) string { return "group gid " + strconv.FormatUint(gid, 10) }
