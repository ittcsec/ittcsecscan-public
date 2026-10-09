package store

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Property 1 (ADR-0010 §3): only well-formed IDs are accepted, and the path
// is always a direct child of the tenants root.

const validID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"

func badTenantIDs() []string {
	cyrillicA := string(rune(0x0430)) // looks like 'a'
	return []string{
		"",
		".",
		"..",
		"../" + validID[:23],
		validID[:25] + "/",
		validID[:25] + `\`,
		"/" + validID[:25],
		`C:` + validID[:24],
		`C:\` + validID[:23],
		`\\?\` + validID[:22],
		`\\server\share` + validID[:12],
		"CON", "NUL", "aux", "com1", "LPT1",
		validID[:24] + ":b", // alternate data stream
		validID[:25] + ".",
		validID[:25] + " ",
		strings.ToUpper(validID),
		validID[:25] + "A",
		cyrillicA + validID[:25],
		validID[:25] + "1", // not in the base32 alphabet
		validID[:25] + "8",
		validID + "a", // too long
		validID[:25],  // too short
		strings.Repeat("a", 4096),
		validID[:25] + "b", // non-canonical: padding bits set
		validID[:12] + "\x00" + validID[:13],
		validID[:12] + "%" + validID[:13],
	}
}

func TestParseTenantIDRejectsEverythingButCanonical(t *testing.T) {
	for _, s := range badTenantIDs() {
		_, err := ParseTenantID(s)
		if !errors.Is(err, ErrInvalidTenantID) {
			t.Errorf("ParseTenantID(%q) error = %v, want ErrInvalidTenantID", s, err)
			continue
		}
		if len(err.Error()) > 120 {
			t.Errorf("error for %d-byte input is %d bytes: it must not echo the input", len(s), len(err.Error()))
		}
	}
}

func TestNewTenantIDsAreCanonicalAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id, err := NewTenantID(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseTenantID(id.String())
		if err != nil || back != id {
			t.Fatalf("NewTenantID produced %q, which does not parse back: %v", id, err)
		}
		if seen[id.String()] {
			t.Fatalf("duplicate tenant ID %q", id)
		}
		seen[id.String()] = true
	}
}

func TestNewTenantIDIsTheReaderOutputOnly(t *testing.T) {
	// The ID is exactly 16 bytes from the reader: nothing else feeds into it.
	a, _ := NewTenantID(bytes.NewReader(make([]byte, 16)))
	if a.String() != validID {
		t.Errorf("16 zero bytes give %q, want %q", a, validID)
	}
	if _, err := NewTenantID(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Error("a short read must fail")
	}
}

func TestLayoutDirIsADirectChild(t *testing.T) {
	root, err := filepath.Abs("data")
	if err != nil {
		t.Fatal(err)
	}
	l, err := newLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		id, _ := NewTenantID(rand.Reader)
		p, err := l.dir(id)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(p) != l.tenantsRoot || filepath.Base(p) != id.String() {
			t.Fatalf("dir(%s) = %s, not a direct child of %s", id, p, l.tenantsRoot)
		}
	}
	if _, err := l.dir(TenantID{}); !errors.Is(err, ErrInvalidTenantID) {
		t.Errorf("the zero TenantID must not resolve, got %v", err)
	}
	if _, err := l.dir(TenantID{s: "../escape-attempt-0000000"}); err == nil {
		t.Error("a hand-built invalid TenantID must not resolve")
	}
	for _, bad := range []string{"relative/data", "/data?x=1", "/data#frag"} {
		if _, err := newLayout(bad); err == nil {
			t.Errorf("newLayout(%q) must fail", bad)
		}
	}
}

func FuzzParseTenantID(f *testing.F) {
	f.Add(validID)
	for _, s := range badTenantIDs() {
		f.Add(s)
	}
	root, err := filepath.Abs("data")
	if err != nil {
		f.Fatal(err)
	}
	l, err := newLayout(root)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseTenantID(s)
		if err != nil {
			return
		}
		if len(s) != tenantIDLen || id.String() != s {
			t.Fatalf("accepted %q as %q", s, id)
		}
		for i := 0; i < len(s); i++ {
			if !isTenantIDChar(s[i]) {
				t.Fatalf("accepted %q with byte %q", s, s[i])
			}
		}
		p, err := l.dir(id)
		if err != nil || filepath.Dir(p) != l.tenantsRoot || filepath.Base(p) != s {
			t.Fatalf("accepted ID %q resolves to %q (%v)", s, p, err)
		}
	})
}
