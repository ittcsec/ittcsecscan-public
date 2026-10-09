package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

func TestClassifyRequiresSubcommand(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "classify")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "subcommand is required") {
		t.Errorf("stderr = %q", r.err)
	}
}

func TestClassifyUnknownSubcommand(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "classify", "frobnicate")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
}

func TestClassifySetValidatesFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no tenant", []string{"classify", "set", "--resource", "arn:aws:s3:::a", "--criticality", "3"}, "--tenant is required"},
		{"no resource", []string{"classify", "set", "--tenant", canonicalTenantID, "--criticality", "3"}, "--resource is required"},
		{"criticality below 1", []string{"classify", "set", "--tenant", canonicalTenantID, "--resource", "arn:aws:s3:::a", "--criticality", "0"}, "--criticality must be 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := invokeCtx(context.Background(), hermetic(t, nil), c.args...)
			if r.code != exitcode.Usage {
				t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
			}
			if !strings.Contains(r.err, c.want) {
				t.Errorf("stderr = %q, want %q", r.err, c.want)
			}
		})
	}
}

func TestClassifyListRequiresTenant(t *testing.T) {
	r := invokeCtx(context.Background(), hermetic(t, nil), "classify", "list")
	if r.code != exitcode.Usage {
		t.Fatalf("code = %s, want usage; stderr=%q", r.code, r.err)
	}
	if !strings.Contains(r.err, "--tenant is required") {
		t.Errorf("stderr = %q", r.err)
	}
}
