package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubKMS is an offline kmsAPI: the same estate in every region, recording each
// call's region, with per-"op@region" error injection.
type stubKMS struct {
	aliases  []kmstypes.AliasListEntry
	keys     []kmstypes.KeyListEntry
	keyPages [][]kmstypes.KeyListEntry // if set, ListKeys paginates
	meta     map[string]kmstypes.KeyMetadata
	policy   map[string]string
	rotation map[string]bool
	tags     map[string][]kmstypes.Tag

	errs    map[string]error
	calls   int
	regions []string
}

func kmsRegion(opts []func(*kms.Options)) string {
	var o kms.Options
	for _, f := range opts {
		f(&o)
	}
	return o.Region
}

func (s *stubKMS) hit(op string, o []func(*kms.Options)) error {
	s.calls++
	r := kmsRegion(o)
	s.regions = append(s.regions, r)
	return s.errs[op+"@"+r]
}

func (s *stubKMS) ListAliases(_ context.Context, _ *kms.ListAliasesInput, o ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if err := s.hit("ListAliases", o); err != nil {
		return nil, err
	}
	return &kms.ListAliasesOutput{Aliases: s.aliases}, nil
}

func (s *stubKMS) ListKeys(_ context.Context, in *kms.ListKeysInput, o ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if err := s.hit("ListKeys", o); err != nil {
		return nil, err
	}
	if len(s.keyPages) > 0 {
		page := 0
		if in.Marker != nil {
			page = int((*in.Marker)[0] - '0')
		}
		out := &kms.ListKeysOutput{}
		if page < len(s.keyPages) {
			out.Keys = s.keyPages[page]
		}
		if page+1 < len(s.keyPages) {
			out.NextMarker = ptr(string(rune('0' + page + 1)))
		}
		return out, nil
	}
	return &kms.ListKeysOutput{Keys: s.keys}, nil
}

func (s *stubKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, o ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if err := s.hit("DescribeKey", o); err != nil {
		return nil, err
	}
	id := deref(in.KeyId)
	if m, ok := s.meta[id]; ok {
		return &kms.DescribeKeyOutput{KeyMetadata: &m}, nil
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyId: in.KeyId}}, nil
}

func (s *stubKMS) GetKeyPolicy(_ context.Context, in *kms.GetKeyPolicyInput, o ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	if err := s.hit("GetKeyPolicy", o); err != nil {
		return nil, err
	}
	p := s.policy[deref(in.KeyId)]
	if p == "" {
		p = "{}"
	}
	return &kms.GetKeyPolicyOutput{Policy: &p}, nil
}

func (s *stubKMS) GetKeyRotationStatus(_ context.Context, in *kms.GetKeyRotationStatusInput, o ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if err := s.hit("GetKeyRotationStatus", o); err != nil {
		return nil, err
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: s.rotation[deref(in.KeyId)]}, nil
}

func (s *stubKMS) ListResourceTags(_ context.Context, in *kms.ListResourceTagsInput, o ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	if err := s.hit("ListResourceTags", o); err != nil {
		return nil, err
	}
	return &kms.ListResourceTagsOutput{Tags: s.tags[deref(in.KeyId)]}, nil
}

func runKMS(t *testing.T, regions []string, api kmsAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newKMSCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func kmsNode(s collect.Scan, arn string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == arn {
			return n, true
		}
	}
	return collect.Node{}, false
}

const cmkArn = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func oneCMKStub() *stubKMS {
	return &stubKMS{
		aliases: []kmstypes.AliasListEntry{{AliasName: ptr("alias/app-data"), TargetKeyId: ptr("k1")}},
		keys:    []kmstypes.KeyListEntry{{KeyId: ptr("k1"), KeyArn: ptr(cmkArn)}},
		meta: map[string]kmstypes.KeyMetadata{"k1": {
			KeyId: ptr("k1"), Arn: ptr(cmkArn), Enabled: true,
			KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled,
			KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt,
			Origin: kmstypes.OriginTypeAwsKms, MultiRegion: bptr(false),
		}},
		policy:   map[string]string{"k1": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"}]}`},
		rotation: map[string]bool{"k1": true},
		tags:     map[string][]kmstypes.Tag{"k1": {{TagKey: ptr("env"), TagValue: ptr("prod")}}},
	}
}

// TestKMSMapsKeys proves a key becomes a control node keyed by ARN, named by its
// alias, with metadata, rotation, tags, and the raw key policy recorded as facts.
func TestKMSMapsKeys(t *testing.T) {
	s := runKMS(t, oneRegion, oneCMKStub())
	n, ok := kmsNode(s, cmkArn)
	if !ok {
		t.Fatal("key not emitted as a control node keyed by ARN")
	}
	if n.Name != "alias/app-data" {
		t.Errorf("name = %q, want the alias", n.Name)
	}
	for k, v := range map[string]string{
		"key_manager": "CUSTOMER", "key_state": "Enabled", "enabled": "true",
		"key_spec": "SYMMETRIC_DEFAULT", "key_usage": "ENCRYPT_DECRYPT", "origin": "AWS_KMS",
		"multi_region": "false", "rotation_enabled": "true", "tag:env": "prod", "region": "us-east-1",
	} {
		if n.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if !strings.Contains(n.Attributes["key_policy"], `"Principal"`) {
		t.Errorf("key_policy not recorded raw: %q", n.Attributes["key_policy"])
	}
	for _, svc := range []string{svcKMSAliases, svcKMSKeys, svcKMSKeyDetails} {
		if c := completenessOf(s, svc); c.Status != collect.Complete {
			t.Errorf("%s = %+v, want complete", svc, c)
		}
	}
}

// TestKMSPolicyRecordedRawNoVerdict proves a policy granting a wildcard principal is
// recorded verbatim with no synthesized "public"/"cross_account" verdict attribute.
func TestKMSPolicyRecordedRawNoVerdict(t *testing.T) {
	api := oneCMKStub()
	api.policy["k1"] = `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`
	s := runKMS(t, oneRegion, api)
	n, _ := kmsNode(s, cmkArn)
	if !strings.Contains(n.Attributes["key_policy"], `"Principal":"*"`) {
		t.Errorf("wildcard policy not recorded raw: %q", n.Attributes["key_policy"])
	}
	for _, forbidden := range []string{"is_public", "public", "cross_account", "policy_is_public"} {
		if _, ok := n.Attributes[forbidden]; ok {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
}

// TestKMSRotationNotApplicableIsFact proves a key type that does not support rotation
// (UnsupportedOperationException) is recorded rotation_enabled "not_applicable" as a
// fact, not a gap: the detail pass stays Complete.
func TestKMSRotationNotApplicableIsFact(t *testing.T) {
	api := oneCMKStub()
	api.errs = map[string]error{"GetKeyRotationStatus@us-east-1": apiErr("UnsupportedOperationException")}
	s := runKMS(t, oneRegion, api)
	n, _ := kmsNode(s, cmkArn)
	if n.Attributes["rotation_enabled"] != "not_applicable" {
		t.Errorf("rotation_enabled = %q, want not_applicable", n.Attributes["rotation_enabled"])
	}
	if c := completenessOf(s, svcKMSKeyDetails); c.Status != collect.Complete {
		t.Errorf("%s = %+v, want complete (not-applicable is a fact, not a gap)", svcKMSKeyDetails, c)
	}
}

// TestKMSInvalidKeyStateIsGap proves a disabled or pending-deletion key that rejects
// a read with KMSInvalidStateException is an honest gap ("invalid key state"), the
// detail pass Partial, and the key node still emitted.
func TestKMSInvalidKeyStateIsGap(t *testing.T) {
	api := oneCMKStub()
	api.errs = map[string]error{"GetKeyPolicy@us-east-1": apiErr("KMSInvalidStateException")}
	s := runKMS(t, oneRegion, api)
	if _, ok := kmsNode(s, cmkArn); !ok {
		t.Error("key node must still be emitted when a read hits an invalid key state")
	}
	if c := completenessOf(s, svcKMSKeyDetails); c.Status != collect.Partial || c.Reason != "invalid key state" {
		t.Errorf("%s = %+v, want partial invalid-key-state", svcKMSKeyDetails, c)
	}
}

// TestKMSDetailDeniedIsGap proves a denied per-key read is a gap, node still emitted.
func TestKMSDetailDeniedIsGap(t *testing.T) {
	api := oneCMKStub()
	api.errs = map[string]error{"DescribeKey@us-east-1": apiErr("AccessDenied")}
	s := runKMS(t, oneRegion, api)
	if _, ok := kmsNode(s, cmkArn); !ok {
		t.Error("key node must still be emitted when DescribeKey is denied")
	}
	if c := completenessOf(s, svcKMSKeyDetails); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcKMSKeyDetails, c)
	}
}

// TestKMSListKeysDeniedIsGap proves a denied ListKeys is a Denied gap with no nodes.
func TestKMSListKeysDeniedIsGap(t *testing.T) {
	api := oneCMKStub()
	api.errs = map[string]error{"ListKeys@us-east-1": apiErr("AccessDenied")}
	s := runKMS(t, oneRegion, api)
	if statusOf(s, svcKMSKeys) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcKMSKeys, statusOf(s, svcKMSKeys))
	}
	if n := nodesByType(s)[model.NodeControl]; n != 0 {
		t.Errorf("control nodes = %d, want 0", n)
	}
}

// TestKMSAliasesDeniedStillCollectsKeys proves a denied ListAliases is a gap that
// does not stop key collection; the key is then named by its id.
func TestKMSAliasesDeniedStillCollectsKeys(t *testing.T) {
	api := oneCMKStub()
	api.errs = map[string]error{"ListAliases@us-east-1": apiErr("AccessDenied")}
	s := runKMS(t, oneRegion, api)
	if statusOf(s, svcKMSAliases) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcKMSAliases, statusOf(s, svcKMSAliases))
	}
	n, ok := kmsNode(s, cmkArn)
	if !ok {
		t.Fatal("key still collected when aliases denied")
	}
	if n.Name != "k1" {
		t.Errorf("name = %q, want the key id fallback", n.Name)
	}
}

// TestKMSRegionNotEnabled proves an opt-in region the account has not enabled, which
// KMS rejects with UnrecognizedClientException (a different code from EC2's
// OptInRequired and RDS's InvalidClientTokenId, all confirmed live), is Unsupported
// "region not enabled".
func TestKMSRegionNotEnabled(t *testing.T) {
	api := &stubKMS{errs: map[string]error{"ListAliases@us-east-1": apiErr("UnrecognizedClientException")}}
	s := runKMS(t, oneRegion, api)
	if c := completenessOf(s, svcKMSAliases); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcKMSAliases, c)
	}
}

// TestKMSBudgetExhaustion proves the shared budget bounds the sweep and marks the
// services not reached Partial "budget exhausted".
func TestKMSBudgetExhaustion(t *testing.T) {
	api := oneCMKStub()
	c := newKMSCollector(acctID, api, oneRegion)
	c.budget = collect.NewBudget(1) // aliases list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 1 {
		t.Errorf("made %d calls under a 1-call budget; want 1", api.calls)
	}
	for _, svc := range []string{svcKMSKeys, svcKMSKeyDetails} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestKMSPaginatesKeys proves the NextMarker is followed across key pages.
func TestKMSPaginatesKeys(t *testing.T) {
	api := &stubKMS{keyPages: [][]kmstypes.KeyListEntry{
		{{KeyId: ptr("a"), KeyArn: ptr("arn:aws:kms:us-east-1:123456789012:key/a")}},
		{{KeyId: ptr("b"), KeyArn: ptr("arn:aws:kms:us-east-1:123456789012:key/b")}},
	}}
	s := runKMS(t, oneRegion, api)
	if c := completenessOf(s, svcKMSKeys); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("%s = %+v, want complete/2 across pages", svcKMSKeys, c)
	}
	if n := nodesByType(s)[model.NodeControl]; n != 2 {
		t.Errorf("keys across pages = %d, want 2", n)
	}
}

// TestKMSEvidenceRedactsToken proves the evidence body is scrubbed.
func TestKMSEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	api := oneCMKStub()
	api.policy["k1"] = `{"token":"` + token + `"}`
	s := runKMS(t, oneRegion, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
