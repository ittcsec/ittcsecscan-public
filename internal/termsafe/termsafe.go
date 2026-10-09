// Package termsafe neutralises control characters in untrusted text before it
// is written to a terminal.
//
// Cloud resource names, tags, file paths, and provider error messages are
// attacker-influenced. Printed verbatim they can carry ANSI/OSC escape sequences
// that rewrite the operator's screen, hide output, or plant hyperlinks, and
// Unicode bidirectional overrides that make text read differently from what it
// is ("Trojan Source"). Every untrusted string written to a terminal goes
// through this package.
package termsafe

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// String returns s with control characters escaped. Newlines and tabs are kept,
// so use it for multi-line free text such as error messages.
func String(s string) string { return sanitize(s, true) }

// Line returns s with control characters escaped, including newlines and tabs.
// Use it for single-line fields so untrusted text cannot forge extra output
// lines.
func Line(s string) string { return sanitize(s, false) }

func sanitize(s string, keepLayout bool) string {
	if isSafe(s, keepLayout) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case keepLayout && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case isControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case isBidiControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isSafe(s string, keepLayout bool) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			return false
		case keepLayout && (r == '\n' || r == '\t'):
		case isControl(r), isBidiControl(r):
			return false
		}
		i += size
	}
	return true
}

// isControl reports C0 controls, DEL, and C1 controls (which some terminals
// interpret as CSI/OSC introducers).
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// isBidiControl reports Unicode bidirectional formatting characters.
func isBidiControl(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
