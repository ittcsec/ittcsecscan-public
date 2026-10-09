package remediate

import (
	"errors"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// ErrDrift is returned when the live state of a target no longer matches the
// state the plan was generated against. The executor refuses to apply on drift.
var ErrDrift = errors.New("remediation refused: target state has drifted since the plan was generated")

// CheckDrift recomputes the current-state hash from freshly re-read entity state
// and compares it to the hash captured in the plan. Any difference is drift: the
// plan was built against a state that no longer holds, so applying it could act
// on unexpected configuration. It is pure and deterministic, and the executor
// calls it immediately before any apply (ADR-0029 section 4). It is the read-only
// half of the "re-read state, stop on drift" invariant; the executor supplies the
// freshly re-read entity.
func CheckDrift(plan GeneratedPlan, current model.Entity) error {
	if CurrentStateHash(current) != plan.CurrentStateHash {
		return ErrDrift
	}
	return nil
}
