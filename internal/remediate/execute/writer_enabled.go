//go:build remediation

package execute

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/providers/aws"
)

// Enabled reports whether provider-write execution is compiled in. Under the
// remediation build tag it is true. Write support is deliberately narrow: only the
// first, fully-proven remediation (AWS S3 public-bucket) is wired. Every other
// finding type is refused (RP-11) until it is separately reviewed and added, the
// same prove-one-thing-completely discipline used elsewhere in the project.
const Enabled = true

// scopedRule is the one finding type wired for write execution.
const scopedRule = "CORE-P0-STORAGE-PUBLIC-AWS"

// publicBucketRemediator removes the public-exposure mechanism from an S3 bucket. It
// is implemented in providers/aws, where the AWS SDK is confined (ADR-0016, ADR-0017),
// so this package never imports the SDK; tests inject a fake. Each method first
// CAPTURES the prior state and returns it, and if the prior state cannot be captured
// it makes no change (fail closed): the tool never changes what it could not record.
type publicBucketRemediator interface {
	// RemovePublicPolicy captures the bucket policy text, then deletes the policy.
	RemovePublicPolicy(ctx context.Context, bucket string) (priorPolicy string, err error)
	// RemovePublicACL captures the ACL grants, then resets the ACL to private.
	RemovePublicACL(ctx context.Context, bucket string) (priorACL string, err error)
}

// DefaultWriter returns the SDK-backed writer. It wires the S3 remediator from
// providers/aws, which resolves the remediation credential profile lazily, so nothing
// is resolved until an approved, drift-checked remediation actually runs.
func DefaultWriter() Writer { return sdkWriter{rem: aws.NewS3Remediator()} }

type sdkWriter struct {
	rem publicBucketRemediator
}

// Apply performs the approved change. It is reached only after Apply's guards
// (remediation profile, apply-ready plan, approval bound to the plan hash, and no
// drift) have all passed. It refuses any finding type other than the scoped S3
// public-bucket rule (RP-11). The bucket comes from the target's collected native id,
// never parsed from display text. It removes exactly the public mechanism(s) the
// finding recorded: a public bucket policy (DeleteBucketPolicy) and/or a public ACL
// (reset ACL to private). Each removal captures the prior state into the receipt. If
// no known public mechanism is present it refuses rather than guess.
func (w sdkWriter) Apply(ctx context.Context, op Operation) (WriteResult, error) {
	if op.Rule.RuleID != scopedRule || op.Target.Provider != model.AWS || op.Action.Service != "s3" {
		return WriteResult{}, fmt.Errorf("remediation write for %s (%s/%s) is not yet wired; it is held for independent review (RP-11)",
			op.Rule.RuleID, op.Target.Provider, op.Action.Service)
	}
	bucket, err := s3BucketName(op.Target.NativeID)
	if err != nil {
		return WriteResult{}, err
	}
	var prior []string
	acted := false
	if op.Target.Attributes["policy_is_public"] == "true" {
		p, err := w.rem.RemovePublicPolicy(ctx, bucket)
		if p != "" {
			prior = append(prior, "policy: "+p)
		}
		if err != nil {
			return WriteResult{PriorState: strings.Join(prior, " | ")}, fmt.Errorf("remove public policy on %s: %w", bucket, err)
		}
		acted = true
	}
	if op.Target.Attributes["acl_all_users"] != "" {
		a, err := w.rem.RemovePublicACL(ctx, bucket)
		if a != "" {
			prior = append(prior, a)
		}
		if err != nil {
			return WriteResult{PriorState: strings.Join(prior, " | ")}, fmt.Errorf("remove public acl on %s: %w", bucket, err)
		}
		acted = true
	}
	if !acted {
		return WriteResult{}, fmt.Errorf("remediation refused: no known public mechanism (policy_is_public or acl_all_users) recorded on %s", bucket)
	}
	return WriteResult{PriorState: strings.Join(prior, " | ")}, nil
}

// s3BucketName extracts the bucket name from a collected S3 bucket native id
// (arn:aws:s3:::<name>). It refuses anything that is not that exact shape, so the
// write target is always a plain bucket name derived from collected data.
func s3BucketName(nativeID string) (string, error) {
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(nativeID, prefix) {
		return "", errors.New("remediation refused: target is not an S3 bucket ARN")
	}
	name := strings.TrimPrefix(nativeID, prefix)
	if name == "" || strings.ContainsAny(name, "/:") {
		return "", errors.New("remediation refused: malformed S3 bucket ARN")
	}
	return name, nil
}
