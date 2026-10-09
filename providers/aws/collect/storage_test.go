package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func bptr(b bool) *bool { return &b }

// stubS3 is an offline storageAPI: it returns canned bucket configuration or an
// injected per-operation error, so the collector is tested with no network and no
// real SDK. Config fields apply to every bucket (tests use one or two).
type stubS3 struct {
	names     []string
	listErr   error
	region    string
	pab       *s3types.PublicAccessBlockConfiguration
	isPublic  *bool
	grants    []s3types.Grant
	encAlg    string
	encKey    string
	verStatus string
	tags      map[string]string

	errLoc, errPAB, errPolicy, errACL, errEnc, errVer, errTag error
	calls                                                     int
}

func (s *stubS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	s.calls++
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := &s3.ListBucketsOutput{}
	for _, n := range s.names {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: ptr(n)})
	}
	return out, nil
}

func (s *stubS3) GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	s.calls++
	if s.errLoc != nil {
		return nil, s.errLoc
	}
	return &s3.GetBucketLocationOutput{LocationConstraint: s3types.BucketLocationConstraint(s.region)}, nil
}

func (s *stubS3) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	s.calls++
	if s.errPAB != nil {
		return nil, s.errPAB
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: s.pab}, nil
}

func (s *stubS3) GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	s.calls++
	if s.errPolicy != nil {
		return nil, s.errPolicy
	}
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: s.isPublic}}, nil
}

func (s *stubS3) GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	s.calls++
	if s.errACL != nil {
		return nil, s.errACL
	}
	return &s3.GetBucketAclOutput{Grants: s.grants}, nil
}

func (s *stubS3) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	s.calls++
	if s.errEnc != nil {
		return nil, s.errEnc
	}
	if s.encAlg == "" {
		return &s3.GetBucketEncryptionOutput{}, nil
	}
	def := &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryption(s.encAlg)}
	if s.encKey != "" {
		def.KMSMasterKeyID = ptr(s.encKey)
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
		Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: def}},
	}}, nil
}

func (s *stubS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	s.calls++
	if s.errVer != nil {
		return nil, s.errVer
	}
	return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatus(s.verStatus)}, nil
}

func (s *stubS3) GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	s.calls++
	if s.errTag != nil {
		return nil, s.errTag
	}
	out := &s3.GetBucketTaggingOutput{}
	for k, v := range s.tags {
		out.TagSet = append(out.TagSet, s3types.Tag{Key: ptr(k), Value: ptr(v)})
	}
	return out, nil
}

func runStorage(t *testing.T, api storageAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newStorageCollector("123456789012", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodesByType(s collect.Scan) map[model.NodeType]int {
	m := map[model.NodeType]int{}
	for _, n := range s.Nodes {
		m[n.Type]++
	}
	return m
}

func nodeNamed(s collect.Scan, tp model.NodeType, native string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == tp && n.NativeID == native {
			return n, true
		}
	}
	return collect.Node{}, false
}

func statusOf(s collect.Scan, service string) collect.Status {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c.Status
		}
	}
	return ""
}

func completenessOf(s collect.Scan, service string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service {
			return c
		}
	}
	return collect.Completeness{}
}

const publicAllUsersURI = "http://acs.amazonaws.com/groups/global/AllUsers"

// TestStorageMapsBuckets proves the buckets become data-store nodes keyed by ARN,
// with region, public-access block, policy public-status, ACL public grant,
// encryption, versioning, and tags recorded as facts, and both enumerations
// Complete.
func TestStorageMapsBuckets(t *testing.T) {
	s := runStorage(t, &stubS3{
		names:  []string{"alpha", "beta"},
		region: "us-west-2",
		pab: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls: bptr(true), IgnorePublicAcls: bptr(true),
			BlockPublicPolicy: bptr(false), RestrictPublicBuckets: bptr(false),
		},
		isPublic:  bptr(false),
		grants:    []s3types.Grant{{Grantee: &s3types.Grantee{URI: ptr(publicAllUsersURI)}, Permission: s3types.PermissionRead}},
		encAlg:    "aws:kms",
		encKey:    "arn:aws:kms:us-west-2:123456789012:key/abc",
		verStatus: "Enabled",
		tags:      map[string]string{"env": "prod"},
	})

	if byType := nodesByType(s); byType[model.NodeDataStore] != 2 {
		t.Fatalf("data-store nodes = %d, want 2", byType[model.NodeDataStore])
	}
	n, ok := nodeNamed(s, model.NodeDataStore, "arn:aws:s3:::alpha")
	if !ok {
		t.Fatal("bucket alpha not keyed by ARN")
	}
	want := map[string]string{
		"region":                      "us-west-2",
		"pab_block_public_acls":       "true",
		"pab_restrict_public_buckets": "false",
		"policy_is_public":            "false",
		"acl_all_users":               "READ",
		"encryption":                  "aws:kms",
		"encryption_kms_key":          "arn:aws:kms:us-west-2:123456789012:key/abc",
		"versioning":                  "Enabled",
		"tag:env":                     "prod",
	}
	for k, v := range want {
		if n.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if statusOf(s, "s3.buckets") != collect.Complete {
		t.Errorf("s3.buckets = %s, want complete", statusOf(s, "s3.buckets"))
	}
	if c := completenessOf(s, "s3.bucketConfig"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("s3.bucketConfig = %+v, want complete with 2", c)
	}
}

// TestStorageNotConfiguredIsData proves an absent sub-resource is recorded as a
// fact, never a gap: the bucket config pass stays Complete and the node carries
// the "none" facts, so an unprotected bucket is visible, not hidden behind a
// denial-shaped gap.
func TestStorageNotConfiguredIsData(t *testing.T) {
	s := runStorage(t, &stubS3{
		names:     []string{"bare"},
		region:    "us-east-1",
		errPAB:    apiErr("NoSuchPublicAccessBlockConfiguration"),
		errPolicy: apiErr("NoSuchBucketPolicy"),
		errEnc:    apiErr("ServerSideEncryptionConfigurationNotFoundError"),
		errTag:    apiErr("NoSuchTagSet"),
	})

	n, ok := nodeNamed(s, model.NodeDataStore, "arn:aws:s3:::bare")
	if !ok {
		t.Fatal("bucket not emitted")
	}
	for k, v := range map[string]string{"public_access_block": "none", "bucket_policy": "none", "encryption": "none"} {
		if n.Attributes[k] != v {
			t.Errorf("attr %s = %q, want %q (absent config must be a fact)", k, n.Attributes[k], v)
		}
	}
	if c := completenessOf(s, "s3.bucketConfig"); c.Status != collect.Complete {
		t.Errorf("s3.bucketConfig = %+v, want complete (absent config is not a gap)", c)
	}
}

// TestStorageDeniedIsGapNotFatal proves a denied per-bucket read is a recorded
// Partial gap, not a run error, and the node is still emitted with what could be
// read.
func TestStorageDeniedIsGapNotFatal(t *testing.T) {
	s := runStorage(t, &stubS3{
		names:  []string{"alpha"},
		region: "eu-west-1",
		errACL: apiErr("AccessDenied"),
	})
	if _, ok := nodeNamed(s, model.NodeDataStore, "arn:aws:s3:::alpha"); !ok {
		t.Error("bucket node must still be emitted when one read is denied")
	}
	if c := completenessOf(s, "s3.bucketConfig"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("s3.bucketConfig = %+v, want partial denied", c)
	}
}

// TestStorageListDeniedIsGap proves a denied ListBuckets is a recorded Denied gap
// with no bucket nodes, not a run error.
func TestStorageListDeniedIsGap(t *testing.T) {
	s := runStorage(t, &stubS3{listErr: apiErr("AccessDenied")})
	if statusOf(s, "s3.buckets") != collect.Denied {
		t.Errorf("s3.buckets = %s, want denied", statusOf(s, "s3.buckets"))
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 0 {
		t.Errorf("data-store nodes = %d, want 0", n)
	}
}

// TestStorageListUnexpectedErrorSurfaces proves an unexpected ListBuckets error is
// recorded Errored and surfaced, never swallowed.
func TestStorageListUnexpectedErrorSurfaces(t *testing.T) {
	var s collect.Scan
	err := newStorageCollector("123456789012", &stubS3{listErr: apiErr("InternalError")}).Collect(context.Background(), &s)
	if err == nil {
		t.Fatal("unexpected error must surface")
	}
	if statusOf(s, "s3.buckets") != collect.Errored {
		t.Errorf("s3.buckets = %s, want error", statusOf(s, "s3.buckets"))
	}
}

// TestStorageBudgetExhaustion proves the shared budget bounds the per-bucket pass:
// with budget for the list plus a couple of reads, the config pass is a Partial
// "budget exhausted" gap.
func TestStorageBudgetExhaustion(t *testing.T) {
	api := &stubS3{names: []string{"alpha"}, region: "us-east-1"}
	c := newStorageCollector("123456789012", api)
	c.budget = collect.NewBudget(3) // ListBuckets + GetBucketLocation + GetPublicAccessBlock, then exhausted
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 3 {
		t.Errorf("made %d calls under a 3-call budget; want 3", api.calls)
	}
	if got := completenessOf(s, "s3.bucketConfig"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("s3.bucketConfig = %+v, want partial budget-exhausted", got)
	}
}

func TestNormalizeRegion(t *testing.T) {
	cases := map[string]string{"": "us-east-1", "EU": "eu-west-1", "us-west-2": "us-west-2"}
	for in, want := range cases {
		if got := normalizeRegion(in); got != want {
			t.Errorf("normalizeRegion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsNotConfigured(t *testing.T) {
	for _, code := range []string{"NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy", "ServerSideEncryptionConfigurationNotFoundError", "NoSuchTagSet"} {
		if !isNotConfigured(apiErr(code)) {
			t.Errorf("%s should be not-configured", code)
		}
	}
	if isNotConfigured(apiErr("AccessDenied")) {
		t.Error("AccessDenied must not be treated as not-configured")
	}
}

// TestStorageEvidenceRedactsToken proves the evidence body is scrubbed.
func TestStorageEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	s := runStorage(t, &stubS3{names: []string{token}, region: "us-east-1"})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token-like value: %s", e.Operation)
		}
	}
}
