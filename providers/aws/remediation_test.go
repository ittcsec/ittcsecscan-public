//go:build remediation

package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3 records the capture reads and the mechanism-removing writes, and lets a test
// force a capture-read failure to exercise the fail-closed behavior.
type fakeS3 struct {
	getPolicyErr error
	getAclErr    error

	deletedPolicy bool
	putACL        s3types.BucketCannedACL
	putACLBucket  string
}

func (f *fakeS3) GetBucketPolicy(_ context.Context, in *awss3.GetBucketPolicyInput, _ ...func(*awss3.Options)) (*awss3.GetBucketPolicyOutput, error) {
	if f.getPolicyErr != nil {
		return nil, f.getPolicyErr
	}
	p := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + *in.Bucket + `/*"}]}`
	return &awss3.GetBucketPolicyOutput{Policy: &p}, nil
}

func (f *fakeS3) DeleteBucketPolicy(_ context.Context, _ *awss3.DeleteBucketPolicyInput, _ ...func(*awss3.Options)) (*awss3.DeleteBucketPolicyOutput, error) {
	f.deletedPolicy = true
	return &awss3.DeleteBucketPolicyOutput{}, nil
}

func (f *fakeS3) GetBucketAcl(_ context.Context, _ *awss3.GetBucketAclInput, _ ...func(*awss3.Options)) (*awss3.GetBucketAclOutput, error) {
	if f.getAclErr != nil {
		return nil, f.getAclErr
	}
	uri := "http://acs.amazonaws.com/groups/global/AllUsers"
	return &awss3.GetBucketAclOutput{Grants: []s3types.Grant{
		{Grantee: &s3types.Grantee{URI: &uri, Type: s3types.TypeGroup}, Permission: s3types.PermissionRead},
	}}, nil
}

func (f *fakeS3) PutBucketAcl(_ context.Context, in *awss3.PutBucketAclInput, _ ...func(*awss3.Options)) (*awss3.PutBucketAclOutput, error) {
	f.putACL = in.ACL
	if in.Bucket != nil {
		f.putACLBucket = *in.Bucket
	}
	return &awss3.PutBucketAclOutput{}, nil
}

func remediatorWith(f *fakeS3) *S3Remediator {
	return &S3Remediator{newClient: func(context.Context) (s3PublicAccessAPI, error) { return f, nil }}
}

// RemovePublicPolicy captures the policy text, then deletes the policy.
func TestRemovePublicPolicyCapturesThenDeletes(t *testing.T) {
	f := &fakeS3{}
	prior, err := remediatorWith(f).RemovePublicPolicy(context.Background(), "acme-policy")
	if err != nil {
		t.Fatalf("RemovePublicPolicy: %v", err)
	}
	if !f.deletedPolicy {
		t.Error("policy was not deleted")
	}
	if !strings.Contains(prior, `"Principal":"*"`) {
		t.Errorf("prior policy text not captured: %q", prior)
	}
}

// RemovePublicACL captures the grants, then resets the ACL to private.
func TestRemovePublicACLCapturesThenPrivatizes(t *testing.T) {
	f := &fakeS3{}
	prior, err := remediatorWith(f).RemovePublicACL(context.Background(), "acme-acl")
	if err != nil {
		t.Fatalf("RemovePublicACL: %v", err)
	}
	if f.putACL != s3types.BucketCannedACLPrivate {
		t.Errorf("ACL was not reset to private, got %q", f.putACL)
	}
	if f.putACLBucket != "acme-acl" {
		t.Errorf("ACL reset on wrong bucket: %q", f.putACLBucket)
	}
	if !strings.Contains(prior, "AllUsers") {
		t.Errorf("prior ACL grants not captured: %q", prior)
	}
}

// Fail closed: if the policy cannot be captured, it is not deleted.
func TestRemovePublicPolicyFailsClosed(t *testing.T) {
	f := &fakeS3{getPolicyErr: errors.New("access denied")}
	if _, err := remediatorWith(f).RemovePublicPolicy(context.Background(), "acme-policy"); err == nil {
		t.Fatal("expected an error when the policy cannot be captured")
	}
	if f.deletedPolicy {
		t.Error("policy was deleted despite being unable to capture it")
	}
}

// Fail closed: if the ACL cannot be captured, it is not changed.
func TestRemovePublicACLFailsClosed(t *testing.T) {
	f := &fakeS3{getAclErr: errors.New("access denied")}
	if _, err := remediatorWith(f).RemovePublicACL(context.Background(), "acme-acl"); err == nil {
		t.Fatal("expected an error when the acl cannot be captured")
	}
	if f.putACL != "" {
		t.Error("acl was changed despite being unable to capture it")
	}
}
