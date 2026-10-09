package remediate

import (
	"errors"
	"testing"
)

// Drift detection: an unchanged target passes; a target whose config changed
// since the plan was generated is refused. Breaking CheckDrift (always returning
// nil) makes the drift case fail.
func TestCheckDrift(t *testing.T) {
	e := awsBucket()
	plan := Plan(ref("CORE-P0-STORAGE-PUBLIC-AWS"), e)

	if err := CheckDrift(plan, awsBucket()); err != nil {
		t.Errorf("unchanged state must not be drift: %v", err)
	}

	drifted := awsBucket()
	drifted.Attributes["policy_is_public"] = "false"
	if err := CheckDrift(plan, drifted); !errors.Is(err, ErrDrift) {
		t.Errorf("a changed attribute must be detected as drift, got %v", err)
	}

	// A different tag is also drift (state includes tags).
	tagged := awsBucket()
	tagged.Tags = map[string]string{"owner": "sec"}
	if err := CheckDrift(plan, tagged); !errors.Is(err, ErrDrift) {
		t.Errorf("a changed tag must be detected as drift, got %v", err)
	}
}
