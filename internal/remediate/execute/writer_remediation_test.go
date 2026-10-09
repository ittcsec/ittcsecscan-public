//go:build remediation

package execute

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/remediate"
)

// fakeRemediator records which mechanism-removal was requested, so the tagged tests
// prove the guarded path without importing the SDK or touching an account.
type fakeRemediator struct {
	policyCalls, aclCalls int
	failPolicy, failACL   error
}

func (f *fakeRemediator) RemovePublicPolicy(_ context.Context, _ string) (string, error) {
	f.policyCalls++
	if f.failPolicy != nil {
		return "", f.failPolicy
	}
	return `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`, nil
}

func (f *fakeRemediator) RemovePublicACL(_ context.Context, _ string) (string, error) {
	f.aclCalls++
	if f.failACL != nil {
		return "", f.failACL
	}
	return "prior acl grants: group:http://acs.amazonaws.com/groups/global/AllUsers=READ", nil
}

func writerWith(f *fakeRemediator) sdkWriter { return sdkWriter{rem: f} }

func sid() model.StableID { return model.StableID(strings.Repeat("a", 64)) }

func policyBucket() model.Entity {
	return model.Entity{ID: sid(), Provider: model.AWS, Type: model.NodeDataStore,
		Name: "acme-policy", NativeID: "arn:aws:s3:::acme-policy",
		Attributes: map[string]string{"policy_is_public": "true"}}
}

func aclBucket() model.Entity {
	return model.Entity{ID: sid(), Provider: model.AWS, Type: model.NodeDataStore,
		Name: "acme-acl", NativeID: "arn:aws:s3:::acme-acl",
		Attributes: map[string]string{"acl_all_users": "READ"}}
}

func storagePlan(e model.Entity) remediate.GeneratedPlan {
	return remediate.Plan(model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS", Version: "1", PackID: "core-p0"}, e)
}

func TestRemediationRemovesPublicPolicy(t *testing.T) {
	e := policyBucket()
	p := storagePlan(e)
	f := &fakeRemediator{}
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e}, writerWith(f))
	if err != nil {
		t.Fatalf("valid remediation refused: %v", err)
	}
	if f.policyCalls != 1 || f.aclCalls != 0 {
		t.Errorf("expected only the policy removal: policy=%d acl=%d", f.policyCalls, f.aclCalls)
	}
	if !rec.Applied || !strings.Contains(rec.PriorState, "policy:") {
		t.Errorf("receipt missing applied/prior policy: %+v", rec)
	}
}

func TestRemediationRemovesPublicACL(t *testing.T) {
	e := aclBucket()
	p := storagePlan(e)
	f := &fakeRemediator{}
	rec, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: e}, writerWith(f))
	if err != nil {
		t.Fatalf("valid remediation refused: %v", err)
	}
	if f.aclCalls != 1 || f.policyCalls != 0 {
		t.Errorf("expected only the acl removal: policy=%d acl=%d", f.policyCalls, f.aclCalls)
	}
	if !rec.Applied || !strings.Contains(rec.PriorState, "acl grants") {
		t.Errorf("receipt missing applied/prior acl: %+v", rec)
	}
}

func TestRemediationRefusedOnDrift(t *testing.T) {
	e := policyBucket()
	p := storagePlan(e)
	drifted := policyBucket()
	drifted.Attributes = map[string]string{"policy_is_public": "false"}
	f := &fakeRemediator{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Remediation, Current: drifted}, writerWith(f))
	if !errors.Is(err, remediate.ErrDrift) {
		t.Fatalf("want ErrDrift, got %v", err)
	}
	if f.policyCalls != 0 || f.aclCalls != 0 {
		t.Error("a real write was requested despite drift")
	}
}

func TestRemediationRefusedWrongProfile(t *testing.T) {
	e := policyBucket()
	p := storagePlan(e)
	f := &fakeRemediator{}
	_, err := Apply(context.Background(), Request{Plan: p, Approval: p.PlanHash, Profile: auth.Discovery, Current: e}, writerWith(f))
	if !errors.Is(err, ErrWrongProfile) {
		t.Fatalf("want ErrWrongProfile, got %v", err)
	}
	if f.policyCalls != 0 || f.aclCalls != 0 {
		t.Error("a real write was requested under a read-only profile")
	}
}

func TestRemediationScopedToOneRule(t *testing.T) {
	f := &fakeRemediator{}
	op := Operation{
		Rule:   model.RuleRef{RuleID: "CORE-P0-COMPUTE-INTERNET-EXPOSED-AWS"},
		Action: model.RemediationAction{Provider: model.AWS, Service: "s3"},
		Target: policyBucket(),
	}
	if _, err := writerWith(f).Apply(context.Background(), op); err == nil || !strings.Contains(err.Error(), "RP-11") {
		t.Fatalf("non-scoped rule must be refused with RP-11, got %v", err)
	}
	if f.policyCalls != 0 || f.aclCalls != 0 {
		t.Error("a write was requested for an unscoped rule")
	}
}

func TestRemediationRefusesNoMechanism(t *testing.T) {
	f := &fakeRemediator{}
	e := model.Entity{Provider: model.AWS, NativeID: "arn:aws:s3:::acme", Attributes: map[string]string{}}
	op := Operation{Rule: model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, Action: model.RemediationAction{Provider: model.AWS, Service: "s3"}, Target: e}
	if _, err := writerWith(f).Apply(context.Background(), op); err == nil || !strings.Contains(err.Error(), "no known public mechanism") {
		t.Fatalf("a bucket with no recorded mechanism must be refused, got %v", err)
	}
	if f.policyCalls != 0 || f.aclCalls != 0 {
		t.Error("a write was requested with no mechanism to remove")
	}
}

func TestRemediationRefusesMalformedTarget(t *testing.T) {
	f := &fakeRemediator{}
	op := Operation{Rule: model.RuleRef{RuleID: "CORE-P0-STORAGE-PUBLIC-AWS"}, Action: model.RemediationAction{Provider: model.AWS, Service: "s3"},
		Target: model.Entity{Provider: model.AWS, NativeID: "not-an-arn", Attributes: map[string]string{"policy_is_public": "true"}}}
	if _, err := writerWith(f).Apply(context.Background(), op); err == nil {
		t.Fatal("malformed target must be refused")
	}
	if f.policyCalls != 0 || f.aclCalls != 0 {
		t.Error("a write was requested for a malformed target")
	}
}
