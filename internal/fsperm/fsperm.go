// Package fsperm reports which principals, besides the current user, can read,
// modify, or replace a file or directory.
//
// The configuration file decides where scan evidence is written, and the data
// directory will hold the local store. Both must be controlled by the
// operator alone. Inspect lists every other principal with access to an entry,
// and InspectAncestors finds folders above it in which another principal could
// swap the entry for one it controls. Callers can then refuse or warn instead
// of assuming.
//
// Trusted principals: the current user; on Windows also LocalSystem and the
// built-in Administrators group; on Unix also root. The administrative
// principals can read and change every file on the machine anyway, so their
// access is not an exposure.
//
// The analysis errs on the side of reporting access rather than hiding it:
//   - Windows deny ACEs are ignored, so access a deny entry would block is still
//     reported. The error is only ever in the safe direction.
//   - Linux POSIX ACLs (access and default) are evaluated. macOS and other
//     Unix ACLs cannot be read without cgo, so those results are marked
//     Incomplete, and a clean result there is not proof of privacy.
package fsperm

import (
	"sort"
	"strings"
)

// Exposure is access held by a principal that is not trusted.
type Exposure struct {
	Principal string
	// Read means the principal can read content (or list a directory).
	Read bool
	// Write means the principal can modify or delete content, or change the
	// entry's permissions or owner.
	Write bool
	// Replace means the principal can delete or rename entries inside this
	// directory (on Windows also the directory itself), or take over its
	// permissions, and so could substitute anything beneath it. It is only
	// meaningful for directories. Replace implies Write.
	Replace bool
}

// Report is the result of Inspect.
type Report struct {
	Path  string
	Owner string
	// Exposures is sorted by Principal and never lists a trusted principal.
	Exposures []Exposure
	// Inherited lists untrusted access that new entries created inside this
	// directory would receive: inheritable Windows ACEs or a Linux default ACL.
	Inherited []Exposure
	// Incomplete is non-empty when the platform check could not cover every
	// access-control mechanism, for example macOS ACLs. An entry without
	// exposures is then not proven private.
	Incomplete string
}

// Inspect reports which untrusted principals can read or modify path. It
// follows symbolic links. It returns an error wrapping errors.ErrUnsupported
// on platforms where permissions cannot be inspected.
func Inspect(path string) (Report, error) { return inspect(path) }

// OthersCanRead reports whether any untrusted principal can read.
func (r Report) OthersCanRead() bool {
	for _, e := range r.Exposures {
		if e.Read {
			return true
		}
	}
	return false
}

// OthersCanWrite reports whether any untrusted principal can modify.
func (r Report) OthersCanWrite() bool {
	for _, e := range r.Exposures {
		if e.Write {
			return true
		}
	}
	return false
}

// OthersCanReplace reports whether any untrusted principal can delete or
// rename entries in this directory.
func (r Report) OthersCanReplace() bool {
	for _, e := range r.Exposures {
		if e.Replace {
			return true
		}
	}
	return false
}

// Describe lists the direct exposures, for example
// "Authenticated Users (read, write); Users (read)".
func (r Report) Describe() string { return describe(r.Exposures) }

// DescribeInherited lists the access new entries would inherit.
func (r Report) DescribeInherited() string { return describe(r.Inherited) }

// DescribeReplace lists the principals that can replace entries.
func (r Report) DescribeReplace() string {
	var names []string
	for _, e := range r.Exposures {
		if e.Replace {
			names = append(names, e.Principal)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "; ")
}

func describe(exposures []Exposure) string {
	if len(exposures) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(exposures))
	for _, e := range exposures {
		var access []string
		if e.Read {
			access = append(access, "read")
		}
		if e.Write {
			access = append(access, "write")
		}
		parts = append(parts, e.Principal+" ("+strings.Join(access, ", ")+")")
	}
	return strings.Join(parts, "; ")
}

// exposureSet merges access per principal.
type exposureSet map[string]*Exposure

func (s exposureSet) add(principal string, read, write, replace bool) {
	if !read && !write && !replace {
		return
	}
	e, ok := s[principal]
	if !ok {
		e = &Exposure{Principal: principal}
		s[principal] = e
	}
	e.Read = e.Read || read
	e.Write = e.Write || write || replace
	e.Replace = e.Replace || replace
}

func (s exposureSet) sorted() []Exposure {
	out := make([]Exposure, 0, len(s))
	for _, e := range s {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal < out[j].Principal })
	return out
}
