package redact

import (
	"fmt"
	"io"
	"log/slog"
)

// Secret holds a sensitive string that must never be rendered.
//
// Every formatting, encoding, and logging path yields Placeholder. The value is
// available only through Reveal, which makes each disclosure explicit and easy
// to find in review. Secret is a struct rather than a named string so that an
// accidental string(s) conversion does not compile.
type Secret struct {
	v string
}

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the wrapped value. Callers must not log, print, persist, or
// return the result across a trust boundary.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer.
func (Secret) String() string { return Placeholder }

// GoString implements fmt.GoStringer so %#v does not expose the field.
func (Secret) GoString() string { return Placeholder }

// Format implements fmt.Formatter so that every verb, including %x and %q,
// renders the placeholder.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Placeholder) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Placeholder + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(Placeholder), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Placeholder) }
