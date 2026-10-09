// Package execute is the remediation executor: the one component allowed to make
// provider changes. It sits behind an experimental build tag. The safety guards
// (credential profile, approval binding, apply-ready check, and drift) are always
// compiled and tested here; only the actual provider-write seam (the Writer
// returned by DefaultWriter) is behind the tag. In the default build DefaultWriter
// refuses, so a normal binary can never mutate a cloud.
//
// This package is intentionally outside the remediate determinism gate (that gate
// skips the execute subpackage): it may resolve credentials and, under the tag,
// call provider SDKs. Provider changes are made through SDK calls, never shell
// interpolation (ADR-0029 section 3; docs/adr/0005-read-only-by-default.md).
package execute

import (
	"context"
	"errors"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
)

var (
	// ErrExecutionDisabled is returned by the default build's writer: provider
	// writes are compiled out until the remediation tag is set and independent
	// review is complete.
	ErrExecutionDisabled = errors.New("remediation execution is disabled: build with -tags remediation and complete independent review to enable provider writes")
	// ErrWrongProfile guards the separate-credential invariant.
	ErrWrongProfile = errors.New("remediation refused: a dedicated remediation credential profile is required, never the read-only scanning profile")
	// ErrApprovalMismatch guards the approval-bound-to-plan-hash invariant.
	ErrApprovalMismatch = errors.New("remediation refused: approval does not match the exact plan hash")
	// ErrNoAction is returned for a plan with no apply-ready action (a named gap).
	ErrNoAction = errors.New("remediation refused: plan has no apply-ready action")
)

// Writer makes an actual provider change for one operation. A Writer is invoked
// ONLY after every guard in Apply has passed. The default build supplies a writer
// that always refuses (ErrExecutionDisabled); the SDK-backed writer is compiled
// only under the remediation build tag. A Writer returns a WriteResult recording the
// exact pre-change state it captured, so the receipt preserves what to restore.
type Writer interface {
	Apply(ctx context.Context, op Operation) (WriteResult, error)
}

// WriteResult is what a Writer reports about a change it made: PriorState is the
// provider-specific, human-readable record of the resource's configuration captured
// immediately before the change, so an operator has an exact record of what to
// restore even though the change is reversible and nothing is deleted.
type WriteResult struct {
	PriorState string
}

// Operation is the fully-guarded change handed to a Writer: the finding's rule, the
// chosen action, and the target entity. The resource to act on is taken from the
// target's collected native id, never parsed from the action's display text, so a
// write can never be misdirected by a formatted string.
type Operation struct {
	Rule   model.RuleRef
	Action model.RemediationAction
	Target model.Entity
}

// ReceiptSink persists an immutable remediation receipt (ADR-0029).
// The store provides the implementation; the executor calls it at every terminal outcome so
// the audit trail records applied and refused attempts alike. It is an interface so the
// executor does not import the store.
type ReceiptSink interface {
	Record(ctx context.Context, r Receipt) error
}

// Request binds an approval to an exact plan and to the freshly re-read live state
// that the drift check compares against.
type Request struct {
	Plan     remediate.GeneratedPlan
	Approval string       // must equal Plan.PlanHash
	Profile  auth.Profile // must be auth.Remediation
	Current  model.Entity // freshly re-read live state, for the drift check
	// Sink persists the receipt. It is required for any real apply so the master-plan
	// immutable-receipt requirement is met; a nil sink is allowed only where nothing is
	// executed (plan-only paths and unit tests that assert guard behavior).
	Sink ReceiptSink
}

// Receipt is the immutable record of an apply attempt, applied or refused. PriorState
// captures the resource's configuration as it was immediately before the change, so a
// human operator can restore it exactly if the change was a mistake, independent of
// the reversible one-command rollback the plan already describes.
type Receipt struct {
	PlanHash   string
	Entity     model.StableID
	Rule       model.RuleRef
	Profile    auth.Profile
	Action     model.RemediationAction
	Applied    bool
	PriorState string
	Refusal    string
}

// Apply runs every safety guard in order and, only if all pass, invokes w to make
// the smallest change and records a receipt. The guard order is deliberate:
//  1. execution must use a dedicated remediation profile, never a read-only
//     scanning profile;
//  2. the plan must carry an apply-ready action (never a named gap);
//  3. the approval must bind to the exact plan hash;
//  4. the target must not have drifted since the plan was generated.
//
// Any guard failure refuses WITHOUT calling w, so nothing is ever written under a
// bad condition. In the default build w is the disabled writer, so even a fully
// valid request cannot write.
func Apply(ctx context.Context, req Request, w Writer) (rec Receipt, err error) {
	rec = Receipt{PlanHash: req.Plan.PlanHash, Entity: req.Plan.Entity, Rule: req.Plan.Finding, Profile: req.Profile}
	// Record the final receipt on every terminal path (applied or refused). A record
	// failure is never silent: after a successful apply it is surfaced as the returned
	// error so the operator knows the change was made but not audited; on an
	// already-failing path it is joined to the original error.
	defer func() {
		if req.Sink == nil {
			return
		}
		if rerr := req.Sink.Record(ctx, rec); rerr != nil {
			if err == nil {
				err = fmt.Errorf("remediation applied but its immutable receipt was not recorded: %w", rerr)
			} else {
				err = errors.Join(err, fmt.Errorf("receipt not recorded: %w", rerr))
			}
		}
	}()
	if err = RequireRemediationProfile(req.Profile); err != nil {
		rec.Refusal = err.Error()
		return rec, err
	}
	if !req.Plan.Available || len(req.Plan.Actions) == 0 {
		rec.Refusal = ErrNoAction.Error()
		return rec, ErrNoAction
	}
	if req.Approval == "" || req.Approval != req.Plan.PlanHash {
		rec.Refusal = ErrApprovalMismatch.Error()
		return rec, ErrApprovalMismatch
	}
	if err = remediate.CheckDrift(req.Plan, req.Current); err != nil {
		rec.Refusal = err.Error()
		return rec, err
	}
	action := smallestAction(req.Plan)
	rec.Action = action
	op := Operation{Rule: req.Plan.Finding, Action: action, Target: req.Current}
	res, werr := w.Apply(ctx, op)
	rec.PriorState = res.PriorState
	if werr != nil {
		rec.Refusal = werr.Error()
		err = werr
		return rec, err
	}
	rec.Applied = true
	return rec, nil
}

// RequireRemediationProfile enforces that execution uses a dedicated remediation
// credential profile, never a read-only scanning profile (ADR-0029 section 3).
func RequireRemediationProfile(p auth.Profile) error {
	if p != auth.Remediation {
		return ErrWrongProfile
	}
	return nil
}

// smallestAction returns the least disruptive action to apply first. The catalog
// orders each plan's actions least-disruptive first, so this is the first action.
func smallestAction(p remediate.GeneratedPlan) model.RemediationAction {
	return p.Actions[0]
}
