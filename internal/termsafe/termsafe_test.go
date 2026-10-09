package termsafe

import (
	"fmt"
	"testing"
	"unicode/utf8"
)

// Control and bidi characters are built from code points at run time so this
// file contains none of the characters it tests for (bidichk stays clean and
// reviewers see exactly what is tested).
func ch(r rune) string { return string(r) }

// esc is the visible form termsafe produces for a bidi control: a backslash,
// "u", and four hex digits.
func esc(r rune) string { return string(rune(0x5c)) + "u" + fmt.Sprintf("%04x", r) }

func TestString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"multi\nline\ttab", "multi\nline\ttab"},
		{"\x1b[31mred\x1b[0m", `\x1b[31mred\x1b[0m`},
		{"osc \x1b]8;;http://evil\x07link", `osc \x1b]8;;http://evil\x07link`},
		{"cr\roverwrite", `cr\x0doverwrite`},
		{"del\x7f", `del\x7f`},
		{"c1 " + ch(0x9b) + " csi", `c1 \x9b csi`},
		{"bidi " + ch(0x202e) + "evil", "bidi " + esc(0x202e) + "evil"},
		{"isolate " + ch(0x2066) + "x" + ch(0x2069), "isolate " + esc(0x2066) + "x" + esc(0x2069)},
		{"marks " + ch(0x200e) + ch(0x200f) + ch(0x061c), "marks " + esc(0x200e) + esc(0x200f) + esc(0x061c)},
		{"bad \xff utf8", `bad \xff utf8`},
		{"unicode ok: äöü 日本", "unicode ok: äöü 日本"},
	}
	for _, tt := range tests {
		if got := String(tt.in); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLineEscapesLayout(t *testing.T) {
	if got := Line("a\nb\tc"); got != `a\x0ab\x09c` {
		t.Errorf("Line = %q", got)
	}
}

func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"", "ok", "\x1b[2J", ch(0x202e), ch(0x9b), "\xff\xfe", "a\nb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for name, out := range map[string]string{"String": String(s), "Line": Line(s)} {
			if !utf8.ValidString(out) {
				t.Fatalf("%s produced invalid UTF-8 for %q", name, s)
			}
			for _, r := range out {
				if name == "String" && (r == '\n' || r == '\t') {
					continue
				}
				if isControl(r) || isBidiControl(r) {
					t.Fatalf("%s left %U in output for %q: %q", name, r, s, out)
				}
			}
		}
		if once := String(s); String(once) != once {
			t.Fatalf("String is not stable on its own output for %q", s)
		}
	})
}
