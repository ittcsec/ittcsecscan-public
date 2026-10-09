//go:build windows

package fsperm

import (
	"strings"
	"testing"
)

func TestWindowsResolver(t *testing.T) {
	if got := windowsResolver("BA"); got != sidAdministrators {
		t.Errorf("BA = %q", got)
	}
	// Every Windows machine has a built-in Administrator account (RID 500),
	// even when it is disabled.
	la := windowsResolver("LA")
	if !strings.HasPrefix(la, "S-1-5-21-") || !strings.HasSuffix(la, "-500") {
		t.Errorf("LA resolved to %q, want S-1-5-21-...-500", la)
	}
	if got := windowsResolver("S-1-5-21-1-2-3-4"); got != "S-1-5-21-1-2-3-4" {
		t.Errorf("full SID changed: %q", got)
	}
	if got := windowsResolver("QQ"); got != "QQ" {
		t.Errorf("unknown alias resolved to %q", got)
	}
}
