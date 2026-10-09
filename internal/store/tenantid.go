package store

import (
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

const (
	// tenantIDBytes is the number of random bytes in a tenant ID.
	tenantIDBytes = 16
	// tenantIDLen is the length of the text form: 16 bytes in unpadded base32.
	tenantIDLen = 26
)

var tenantIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TenantID identifies a tenant (ADR-0010 §1). It is 128 random bits, written
// as 26 lowercase base32 characters, and never derived from a name or any
// other identifier. The zero value is not a valid ID.
type TenantID struct{ s string }

// NewTenantID draws a new tenant ID from r, which must be a cryptographically
// secure source such as crypto/rand.Reader.
func NewTenantID(r io.Reader) (TenantID, error) {
	var b [tenantIDBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return TenantID{}, fmt.Errorf("store: generating tenant ID: %w", err)
	}
	return TenantID{s: strings.ToLower(tenantIDEncoding.EncodeToString(b[:]))}, nil
}

// ParseTenantID accepts only the canonical form: exactly 26 characters from
// [a-z2-7] that decode to 16 bytes and encode back to the same text. Anything
// else is rejected, including path separators, dots, drive letters, upper
// case, and Unicode lookalikes. The error never echoes the input.
func ParseTenantID(s string) (TenantID, error) {
	if len(s) != tenantIDLen {
		return TenantID{}, fmt.Errorf("%w: want %d characters, got %d bytes", ErrInvalidTenantID, tenantIDLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		if !isTenantIDChar(s[i]) {
			return TenantID{}, fmt.Errorf("%w: byte %d is outside [a-z2-7]", ErrInvalidTenantID, i+1)
		}
	}
	b, err := tenantIDEncoding.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != tenantIDBytes || strings.ToLower(tenantIDEncoding.EncodeToString(b)) != s {
		return TenantID{}, fmt.Errorf("%w: not a canonical encoding", ErrInvalidTenantID)
	}
	return TenantID{s: s}, nil
}

func isTenantIDChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= '2' && c <= '7':
		return true
	default:
		return false
	}
}

// String returns the canonical text form.
func (t TenantID) String() string { return t.s }

// IsZero reports whether t is the zero value.
func (t TenantID) IsZero() bool { return t.s == "" }
