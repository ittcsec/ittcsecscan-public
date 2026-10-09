package main

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
)

func TestUpdateHelp(t *testing.T) {
	env := hermetic(t, nil)
	r := invoke(t, env, "help", "update")
	if r.code != exitcode.OK {
		t.Fatalf("help update: exit=%v", r.code)
	}
	for _, want := range []string{"check", "status", "offline", "rollback", "signed", "no inventory"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("help update missing %q\n%s", want, r.out)
		}
	}
}

func TestUpdateSubcommandErrors(t *testing.T) {
	env := hermetic(t, nil)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"update"}, "expected a subcommand"},
		{"unknown subcommand", []string{"update", "bogus"}, "unknown subcommand"},
		{"check needs repo", []string{"update", "check"}, "--repo is required"},
		{"rollback needs component", []string{"update", "rollback"}, "--component is required"},
		{"offline needs root", []string{"update", "offline", "some-bundle"}, "pinned trust root is required"},
		{"offline needs a bundle", []string{"update", "offline"}, "exactly one bundle"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := invoke(t, env, tt.args...)
			if r.code != exitcode.Usage {
				t.Errorf("exit=%v, want usage; err=%q", r.code, r.err)
			}
			if !strings.Contains(r.err, tt.want) {
				t.Errorf("stderr %q does not contain %q", r.err, tt.want)
			}
		})
	}
}

func TestUpdateStatusEmpty(t *testing.T) {
	env := hermetic(t, nil)
	r := invoke(t, env, "update", "status")
	if r.code != exitcode.OK {
		t.Fatalf("update status: exit=%v err=%q", r.code, r.err)
	}
	if !strings.Contains(r.out, "no components installed") {
		t.Errorf("unexpected status output: %q", r.out)
	}
}
