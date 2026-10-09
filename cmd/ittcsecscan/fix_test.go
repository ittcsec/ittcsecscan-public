package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

func fixEntries() []fixEntry {
	bkt := model.Entity{ID: "sid1", Provider: model.AWS, Type: model.NodeDataStore, Name: "pub", NativeID: "arn:aws:s3:::pub", Attributes: map[string]string{"policy_is_public": "true"}}
	comp := model.Entity{ID: "sid2", Provider: model.AWS, Type: model.NodeCompute, Name: "i-1", NativeID: "i-1"}
	return []fixEntry{
		{Plan: remediate.Plan(model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, bkt), Native: "arn:aws:s3:::pub", Risk: 35},
		{Plan: remediate.Plan(model.RuleRef{RuleID: "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS"}, comp), Native: "i-1", Risk: 31},
	}
}

func TestWriteFixPlansShowsRealGuidanceAndGap(t *testing.T) {
	var b bytes.Buffer
	if err := writeFixPlans(&b, false, store.TenantID{}, fixEntries()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"plan-only", "aws s3api delete-bucket-policy", "plan hash:", "cli:", "gap:", "RP-6"} {
		if !strings.Contains(s, want) {
			t.Errorf("plan output missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "—") || strings.Contains(s, "–") {
		t.Error("plan output contains a forbidden dash")
	}
}

func TestWriteFixSimulationIsDryRunAndNamesGuards(t *testing.T) {
	var b bytes.Buffer
	if err := writeFixSimulation(&b, false, store.TenantID{}, fixEntries()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{"DRY RUN", "would apply the smallest action", "required credential profile: remediation", "drift guard", "disabled", "nothing was changed"} {
		if !strings.Contains(s, want) {
			t.Errorf("simulation output missing %q\n%s", want, s)
		}
	}
}

func TestWriteFixPlansEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := writeFixPlans(&b, false, store.TenantID{}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "nothing to remediate") {
		t.Errorf("empty plan output: %q", b.String())
	}
}

func TestFixHelpAndUsage(t *testing.T) {
	env := hermetic(t, nil)

	r := invoke(t, env, "help", "fix")
	if r.code != exitcode.OK || !strings.Contains(r.out, "plan-only") || !strings.Contains(r.out, "simulate") {
		t.Errorf("help fix: exit=%v out=%q", r.code, r.out)
	}

	r = invoke(t, env, "fix")
	if r.code != exitcode.Usage || !strings.Contains(r.err, "expected a subcommand") {
		t.Errorf("fix with no subcommand: exit=%v err=%q", r.code, r.err)
	}

	r = invoke(t, env, "fix", "bogus")
	if r.code != exitcode.Usage || !strings.Contains(r.err, "unknown subcommand") {
		t.Errorf("fix bogus: exit=%v err=%q", r.code, r.err)
	}
}
