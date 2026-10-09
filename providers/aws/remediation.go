//go:build remediation

package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// This file is compiled only under the remediation build tag, so the default binary
// never contains a write-capable client. It is the one place S3 writes live, because
// the AWS SDK is confined to providers/aws (ADR-0016, ADR-0017). Every change is made
// through SDK calls, never shell interpolation, and only after the executor's guards
// have passed. Each change first CAPTURES the prior state and returns it, and if the
// prior state cannot be captured it makes no change (fail closed).

// s3PublicAccessAPI is the S3 surface the remediator uses: capture reads and the two
// mechanism-removing writes. It is an interface so tests inject a fake and never touch
// the network or a real account.
type s3PublicAccessAPI interface {
	GetBucketPolicy(ctx context.Context, in *awss3.GetBucketPolicyInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketPolicyOutput, error)
	DeleteBucketPolicy(ctx context.Context, in *awss3.DeleteBucketPolicyInput, optFns ...func(*awss3.Options)) (*awss3.DeleteBucketPolicyOutput, error)
	GetBucketAcl(ctx context.Context, in *awss3.GetBucketAclInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketAclOutput, error)
	PutBucketAcl(ctx context.Context, in *awss3.PutBucketAclInput, optFns ...func(*awss3.Options)) (*awss3.PutBucketAclOutput, error)
}

// S3Remediator removes the public-exposure mechanism from an S3 bucket, using the
// REMEDIATION credential profile (never the read-only Discovery profile the scanner
// uses).
type S3Remediator struct {
	// newClient resolves the remediation profile and returns the S3 client.
	// Overridable in tests.
	newClient func(ctx context.Context) (s3PublicAccessAPI, error)
}

// NewS3Remediator returns a remediator that resolves the remediation credential
// profile lazily. Resolving the profile also establishes the caller identity, so a
// bad or missing remediation credential fails before any change is attempted.
func NewS3Remediator() *S3Remediator {
	return &S3Remediator{
		newClient: func(ctx context.Context) (s3PublicAccessAPI, error) {
			a := New()
			_, cfg, err := a.resolveConfig(ctx, model.AWS, auth.Remediation)
			if err != nil {
				return nil, err
			}
			return awss3.NewFromConfig(cfg), nil
		},
	}
}

// RemovePublicPolicy captures the bucket's current policy text, then deletes the
// policy. The captured policy is returned for the receipt so an operator can recreate
// it if the removal was a mistake (DeleteBucketPolicy is not otherwise reversible). If
// the policy cannot be captured, nothing is deleted (fail closed).
func (r *S3Remediator) RemovePublicPolicy(ctx context.Context, bucket string) (string, error) {
	client, err := r.newClient(ctx)
	if err != nil {
		return "", err
	}
	out, err := client.GetBucketPolicy(ctx, &awss3.GetBucketPolicyInput{Bucket: &bucket})
	if err != nil {
		return "", fmt.Errorf("capture bucket policy for %s: %w", bucket, err)
	}
	prior := ""
	if out.Policy != nil {
		prior = *out.Policy
	}
	if _, err := client.DeleteBucketPolicy(ctx, &awss3.DeleteBucketPolicyInput{Bucket: &bucket}); err != nil {
		return prior, err
	}
	return prior, nil
}

// RemovePublicACL captures the bucket's current ACL grants, then resets the ACL to
// private (owner full control only, all other grants removed). The captured grants are
// returned for the receipt. If the ACL cannot be captured, nothing is changed (fail
// closed).
func (r *S3Remediator) RemovePublicACL(ctx context.Context, bucket string) (string, error) {
	client, err := r.newClient(ctx)
	if err != nil {
		return "", err
	}
	out, err := client.GetBucketAcl(ctx, &awss3.GetBucketAclInput{Bucket: &bucket})
	if err != nil {
		return "", fmt.Errorf("capture bucket acl for %s: %w", bucket, err)
	}
	prior := formatGrants(out)
	if _, err := client.PutBucketAcl(ctx, &awss3.PutBucketAclInput{Bucket: &bucket, ACL: s3types.BucketCannedACLPrivate}); err != nil {
		return prior, err
	}
	return prior, nil
}

// formatGrants renders an ACL's grants into a stable, human-readable record for the
// receipt (grantee then permission, sorted), so the prior access is preserved exactly.
func formatGrants(out *awss3.GetBucketAclOutput) string {
	if out == nil {
		return "no acl returned"
	}
	var lines []string
	for _, g := range out.Grants {
		grantee := "unknown"
		if g.Grantee != nil {
			switch {
			case g.Grantee.URI != nil && *g.Grantee.URI != "":
				grantee = "group:" + *g.Grantee.URI
			case g.Grantee.ID != nil && *g.Grantee.ID != "":
				grantee = "id:" + *g.Grantee.ID
			}
		}
		lines = append(lines, grantee+"="+string(g.Permission))
	}
	sort.Strings(lines)
	return "prior acl grants: " + strings.Join(lines, ", ")
}
