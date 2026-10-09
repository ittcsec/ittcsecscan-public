package model_test

import (
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// checkEnum asserts a string enum's vocabulary is non-empty, unique, all
// Valid, and that an unknown value is rejected.
func checkEnum[T ~string](t *testing.T, name string, all []T, valid func(T) bool) {
	t.Helper()
	if len(all) == 0 {
		t.Fatalf("%s: empty vocabulary", name)
	}
	seen := map[T]bool{}
	for _, v := range all {
		if v == "" {
			t.Errorf("%s: empty value", name)
		}
		if seen[v] {
			t.Errorf("%s: %q repeated", name, v)
		}
		seen[v] = true
		if !valid(v) {
			t.Errorf("%s: %q is listed but not Valid()", name, v)
		}
	}
	if valid(T("__not_a_value__")) {
		t.Errorf("%s: an unknown value was accepted", name)
	}
}

func TestEnumsAreValidAndClosed(t *testing.T) {
	checkEnum(t, "provider", model.Providers, model.Provider.Valid)
	checkEnum(t, "node type", model.NodeTypes, model.NodeType.Valid)
	checkEnum(t, "edge kind", model.EdgeKinds, model.EdgeKind.Valid)
	checkEnum(t, "outcome", model.Outcomes, model.Outcome.Valid)
	checkEnum(t, "scan status", model.ScanStatuses, model.ScanStatus.Valid)
	checkEnum(t, "change", model.Changes, model.Change.Valid)
	checkEnum(t, "freshness", model.Freshnesses, model.Freshness.Valid)
	checkEnum(t, "completeness", model.Completenesses, model.Completeness.Valid)
	checkEnum(t, "tri-state", model.TriStates, model.TriState.Valid)

	// The graph vocabularies match the canonical model's counts.
	if len(model.NodeTypes) != 33 || len(model.EdgeKinds) != 25 {
		t.Errorf("the canonical model lists 33 node types and 24 edge kinds plus expansion edges; model has %d and %d", len(model.NodeTypes), len(model.EdgeKinds))
	}
	// Outcomes never fold unknown or error into pass.
	if !model.OutcomeUnknown.Valid() || model.OutcomeUnknown == model.Pass {
		t.Error("unknown must be a distinct, valid outcome")
	}
}

func TestStableIDAndConfidenceValidation(t *testing.T) {
	for _, ok := range []string{strings.Repeat("0", 64), strings.Repeat("a", 64), "0123456789abcdef" + strings.Repeat("0", 48)} {
		if !model.StableID(ok).Valid() {
			t.Errorf("%q should be a valid stable ID", ok)
		}
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("A", 64), strings.Repeat("0", 63), strings.Repeat("0", 65)} {
		if model.StableID(bad).Valid() {
			t.Errorf("%q should be an invalid stable ID", bad)
		}
	}
	for c := -1; c <= 101; c++ {
		want := c >= 0 && c <= 100
		if model.Confidence(c).Valid() != want {
			t.Errorf("Confidence(%d).Valid() = %v, want %v", c, model.Confidence(c).Valid(), want)
		}
	}
}
