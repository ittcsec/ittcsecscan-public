package fsperm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Windows access-mask bits (winnt.h) that decide read, write, or replace
// exposure.
const (
	fileReadData    = 0x1 // FILE_LIST_DIRECTORY on directories
	fileWriteData   = 0x2 // FILE_ADD_FILE on directories
	fileAppendData  = 0x4 // FILE_ADD_SUBDIRECTORY on directories
	fileDeleteChild = 0x40
	accessDelete    = 0x10000
	writeDAC        = 0x40000
	writeOwner      = 0x80000
	genericAll      = 0x10000000
	genericExecute  = 0x20000000
	genericWrite    = 0x40000000
	genericRead     = 0x80000000

	readMask  = fileReadData | genericRead | genericAll
	writeMask = fileWriteData | fileAppendData | fileDeleteChild | accessDelete |
		writeDAC | writeOwner | genericWrite | genericAll
	// replaceMask: delete or rename entries in a directory (or the directory
	// itself), or grant oneself those rights. GENERIC_WRITE maps to
	// FILE_GENERIC_WRITE, which includes neither DELETE nor FILE_DELETE_CHILD.
	replaceMask = fileDeleteChild | accessDelete | writeDAC | writeOwner | genericAll
)

// rightTokens maps SDDL access-right abbreviations to mask bits.
var rightTokens = map[string]uint32{
	"GA": genericAll, "GR": genericRead, "GW": genericWrite, "GX": genericExecute,
	"FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0,
	"SD": accessDelete, "RC": 0x20000, "WD": writeDAC, "WO": writeOwner,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20,
	"DT": 0x40, "LO": 0x80, "CR": 0x100,
}

type wellKnown struct{ sid, name string }

// aliases maps machine-independent SDDL SID abbreviations to SIDs and display
// names.
var aliases = map[string]wellKnown{
	"SY": {"S-1-5-18", "SYSTEM"},
	"BA": {"S-1-5-32-544", "Administrators"},
	"BU": {"S-1-5-32-545", "Users"},
	"BG": {"S-1-5-32-546", "Guests"},
	"PU": {"S-1-5-32-547", "Power Users"},
	"RD": {"S-1-5-32-555", "Remote Desktop Users"},
	"AU": {"S-1-5-11", "Authenticated Users"},
	"WD": {"S-1-1-0", "Everyone"},
	"AN": {"S-1-5-7", "Anonymous"},
	"IU": {"S-1-5-4", "Interactive"},
	"NU": {"S-1-5-2", "Network"},
	"SU": {"S-1-5-6", "Service"},
	"LS": {"S-1-5-19", "Local Service"},
	"NS": {"S-1-5-20", "Network Service"},
	"CO": {"S-1-3-0", "Creator Owner"},
	"CG": {"S-1-3-1", "Creator Group"},
	"OW": {"S-1-3-4", "Owner Rights"},
	"AC": {"S-1-15-2-1", "All Application Packages"},
}

// relativeAliases are SDDL abbreviations whose SID depends on the machine or
// domain (for example "LA" is <machine SID>-500, the built-in Administrator
// account). They cannot be resolved from a table; see Resolver.
var relativeAliases = map[string]string{
	"LA": "local Administrator account",
	"LG": "local Guest account",
	"DA": "Domain Admins",
	"DU": "Domain Users",
	"DG": "Domain Guests",
	"DC": "Domain Computers",
	"DD": "Domain Controllers",
	"EA": "Enterprise Admins",
	"SA": "Schema Admins",
}

var namesBySID = func() map[string]string {
	m := make(map[string]string, len(aliases))
	for _, a := range aliases {
		m[a.sid] = a.name
	}
	return m
}()

const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidCreatorOwner   = "S-1-3-0"
	sidOwnerRights    = "S-1-3-4"
)

// Resolver turns an SDDL trustee (a SID string or a two-letter alias) into a
// SID string. It returns its input unchanged when it cannot resolve it; an
// unresolved trustee is never trusted.
type Resolver func(trustee string) string

// staticResolver resolves only machine-independent aliases. The Windows
// inspector adds the operating system's own resolution for machine- and
// domain-relative aliases such as "LA".
func staticResolver(trustee string) string {
	if a, ok := aliases[trustee]; ok {
		return a.sid
	}
	return trustee
}

// sddlHeader matches the owner, optional group, and DACL flags of a security
// descriptor string requested with OWNER and DACL information.
var sddlHeader = regexp.MustCompile(`^O:(S-1-[0-9-]+|[A-Z]{2})(?:G:(?:S-1-[0-9-]+|[A-Z]{2}))?D:([A-Z_]*)`)

// sddlTrustee matches an ACE trustee: a SID string or a two-letter alias.
var sddlTrustee = regexp.MustCompile(`^(S-1-[0-9]+(-[0-9]+)*|[A-Z]{2})$`)

// evaluateSDDL computes the exposures described by a security descriptor in
// SDDL form for the user identified by currentUser (a SID string). It is
// platform-independent so the Windows logic is tested on every OS.
func evaluateSDDL(path, sddl, currentUser string, resolve Resolver) (Report, error) {
	m := sddlHeader.FindStringSubmatch(sddl)
	if m == nil {
		return Report{}, fmt.Errorf("unrecognised security descriptor %q", sddl)
	}
	ownerRaw, daclFlags := m[1], m[2]
	owner := resolve(ownerRaw)
	rep := Report{Path: path, Owner: display(ownerRaw)}
	set, inherited := exposureSet{}, exposureSet{}

	ownerTrusted := owner == currentUser || systemPrincipal(owner)
	if !ownerTrusted {
		// An owner can always rewrite the DACL.
		set.add(display(ownerRaw)+" (owner)", false, true, true)
	}
	if strings.Contains(daclFlags, "NO_ACCESS_CONTROL") {
		set.add("Everyone (no DACL)", true, true, true)
		rep.Exposures = set.sorted()
		return rep, nil
	}

	rest := sddl[len(m[0]):]
	for strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return Report{}, fmt.Errorf("unterminated ACE in security descriptor %q", sddl)
		}
		ace := aceContext{currentUser: currentUser, ownerTrusted: ownerTrusted, resolve: resolve, direct: set, inherited: inherited}
		if err := ace.evaluate(rest[1:end]); err != nil {
			return Report{}, fmt.Errorf("security descriptor %q: %w", sddl, err)
		}
		rest = rest[end+1:]
	}
	if rest != "" && !strings.HasPrefix(rest, "S:") {
		return Report{}, fmt.Errorf("unexpected data %q in security descriptor", rest)
	}
	rep.Exposures, rep.Inherited = set.sorted(), inherited.sorted()
	return rep, nil
}

type aceContext struct {
	currentUser  string
	ownerTrusted bool
	resolve      Resolver
	direct       exposureSet
	inherited    exposureSet
}

func (c aceContext) evaluate(ace string) error {
	f := strings.Split(ace, ";")
	if len(f) < 6 {
		return fmt.Errorf("malformed ACE %q", ace)
	}
	aceType, aceFlags, rights, principal := f[0], f[1], f[2], f[5]
	if !sddlTrustee.MatchString(principal) {
		// Without a well-formed trustee we cannot say who holds the access,
		// so the whole descriptor is unevaluable rather than guessed.
		return fmt.Errorf("ACE %q has no valid trustee", ace)
	}
	switch aceType {
	case "D", "OD", "XD":
		// Deny entries only remove access. Ignoring them can over-report
		// exposure but never hide it.
		return nil
	case "A", "OA", "XA", "ZA":
	default:
		return fmt.Errorf("unsupported ACE type %q", aceType)
	}
	mask, err := parseRights(rights)
	if err != nil {
		return err
	}
	inheritOnly := hasToken(aceFlags, "IO")
	inheritable := hasToken(aceFlags, "OI") || hasToken(aceFlags, "CI")

	sid := c.resolve(principal)
	trusted := sid == c.currentUser || systemPrincipal(sid) || appContainerSID(sid)
	read, write, replace := mask&readMask != 0, mask&writeMask != 0, mask&replaceMask != 0
	name := display(principal)

	if !inheritOnly && !trusted && (sid != sidOwnerRights || !c.ownerTrusted) {
		c.direct.add(name, read, write, replace)
	}
	// A new entry is owned by its creator (the current user), so Creator
	// Owner and Owner Rights grants on children are not exposures.
	if inheritable && !trusted && sid != sidCreatorOwner && sid != sidOwnerRights {
		c.inherited.add(name, read, write, false)
	}
	return nil
}

func parseRights(s string) (uint32, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid access mask %q", s)
		}
		return uint32(v), nil
	}
	if s != "" && strings.Trim(s, "0123456789") == "" {
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid access mask %q", s)
		}
		return uint32(v), nil
	}
	if len(s)%2 != 0 {
		return 0, fmt.Errorf("invalid access rights %q", s)
	}
	var mask uint32
	for i := 0; i < len(s); i += 2 {
		bits, ok := rightTokens[s[i:i+2]]
		if !ok {
			return 0, fmt.Errorf("unknown access right %q", s[i:i+2])
		}
		mask |= bits
	}
	return mask, nil
}

// hasToken reports whether a string of two-letter SDDL flags contains tok.
func hasToken(flags, tok string) bool {
	for i := 0; i+2 <= len(flags); i += 2 {
		if flags[i:i+2] == tok {
			return true
		}
	}
	return false
}

func display(principal string) string {
	if a, ok := aliases[principal]; ok {
		return a.name
	}
	if name, ok := relativeAliases[principal]; ok {
		return name
	}
	if name, ok := namesBySID[principal]; ok {
		return name
	}
	return principal
}
