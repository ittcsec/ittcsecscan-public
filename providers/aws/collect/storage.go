package collect

import (
	"context"
	"encoding/json"
	"errors"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// storageCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const storageCollectorID = "collector:aws.s3.buckets"

// s3APIVersion is the S3 API version, recorded as evidence provenance.
const s3APIVersion = "2006-03-01"

// storageAPI is the read-only S3 surface the collector uses. Every operation is a
// read-only bucket-metadata GET, verified against the S3 API reference
// (2026-09-19); none reads object listings or contents (GetObject and
// SelectObjectContent, which the read-only gate forbids). Each per-bucket call
// takes optFns so the collector can target the bucket's own region.
type storageAPI interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
}

// StorageCollector reads the account's S3 buckets and their security-relevant
// configuration (region, public-access block, policy public-status, ACL public
// grants, default encryption, versioning, and tags), the first sensitive-asset
// collector (ADR-0019). It records the provider's own facts and does not
// synthesize an "is public" verdict: that determination belongs to the rule and
// reachability engines. Object listings and contents are never read.
//
// S3 is a special case of ADR-0019 §1 regional enumeration: ListBuckets is a
// single global call, so this collector does not fan out over a region set; each
// bucket's region comes from GetBucketLocation and is recorded as an attribute
// (and used to target the per-bucket reads at the bucket's region).
type StorageCollector struct {
	account string
	api     storageAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewStorageCollector builds the collector with a read-only S3 client from the
// adapter's resolved config (ADR-0018 §3). budget is the scan's shared call cap
// (nil is unlimited).
func NewStorageCollector(account string, cfg awssdk.Config, budget *collect.Budget) *StorageCollector {
	return &StorageCollector{account: account, api: s3.NewFromConfig(cfg), budget: budget}
}

// newStorageCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newStorageCollector(account string, api storageAPI) *StorageCollector {
	return &StorageCollector{account: account, api: api}
}

func (c *StorageCollector) ID() string               { return storageCollectorID }
func (c *StorageCollector) Provider() model.Provider { return model.AWS }

// storageRequirements are the read-only permissions this collector needs,
// credited to it. The IAM action names were verified against the S3 service
// authorization reference (2026-09-19); several differ from the API operation
// name (ListBuckets -> s3:ListAllMyBuckets, GetPublicAccessBlock ->
// s3:GetBucketPublicAccessBlock, GetBucketEncryption ->
// s3:GetEncryptionConfiguration). They are registered at init so the templates
// reconcile against real code (ADR-0016).
func storageRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: storageCollectorID}
	}
	return []permissions.Requirement{
		req("s3:ListAllMyBuckets"),
		req("s3:GetBucketLocation"),
		req("s3:GetBucketPublicAccessBlock"),
		req("s3:GetBucketPolicyStatus"),
		req("s3:GetBucketAcl"),
		req("s3:GetEncryptionConfiguration"),
		req("s3:GetBucketVersioning"),
		req("s3:GetBucketTagging"),
	}
}

func init() {
	for _, r := range storageRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *StorageCollector) Requirements() []permissions.Requirement { return storageRequirements() }

// Collect lists the account's buckets, then reads each bucket's configuration.
// Two completeness records are produced: s3.buckets (the list) and s3.bucketConfig
// (the per-bucket metadata pass). An absent sub-resource (no public-access block,
// no policy, no default encryption, no tags) is recorded as a fact, never as a
// gap: misreporting an absent protection as a denial would hide a real weakness.
func (c *StorageCollector) Collect(ctx context.Context, sink collect.Sink) error {
	buckets, err := c.listBuckets(ctx, sink)
	if err != nil {
		return err
	}
	return c.configureBuckets(ctx, sink, buckets)
}

// listBuckets reads the account's bucket list, paginating fully or recording a
// gap. A denied or throttled read is a represented gap (and nil buckets, so there
// is nothing to configure); an unexpected error is surfaced.
func (c *StorageCollector) listBuckets(ctx context.Context, sink collect.Sink) ([]bucketRef, error) {
	const service = "s3.buckets"
	var out []bucketRef
	in := &s3.ListBucketsInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: len(out), Reason: "cancelled"})
			return nil, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: len(out), Reason: "budget exhausted"})
			return out, nil
		}
		page, err := c.api.ListBuckets(ctx, in)
		if err != nil {
			_ = sink.Complete(c.completeness(service, collect.Global, "", len(out), err))
			if isDenied(err) || isThrottle(err) {
				return nil, nil
			}
			return nil, err
		}
		_ = sink.Evidence(c.evidence("ListBuckets", collect.Global, "", page))
		for _, b := range page.Buckets {
			if name := deref(b.Name); name != "" {
				out = append(out, bucketRef{name: name})
			}
		}
		if page.ContinuationToken == nil || *page.ContinuationToken == "" {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Complete, Collected: len(out)})
			return out, nil
		}
		in.ContinuationToken = page.ContinuationToken
	}
}

// bucketRef is a bucket to configure: just its name (its region is discovered
// during configuration).
type bucketRef struct{ name string }

// configureBuckets reads each bucket's configuration and records one aggregate
// completeness for the pass. A single bucket's denied or errored read is a
// recorded gap that does not stop the others; budget exhaustion stops the pass
// and is a Partial "budget exhausted" gap. An absent sub-resource is not a gap.
func (c *StorageCollector) configureBuckets(ctx context.Context, sink collect.Sink, buckets []bucketRef) error {
	const service = "s3.bucketConfig"
	done := 0
	reason := ""
	for _, b := range buckets {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: collect.Partial, Collected: done, Reason: "cancelled"})
			return err
		}
		gap := c.configureBucket(ctx, sink, b.name)
		if gap == "budget exhausted" {
			reason = gap
			break
		}
		if gap != "" {
			reason = gap
			continue
		}
		done++
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: c.scope(), Status: status, Collected: done, Reason: reason})
	return nil
}

// configureBucket gathers one bucket's configuration into attributes and emits the
// node once (keyed by ARN per ADR-0019 §2). It returns "" when every read
// completed (including reads that found an absent sub-resource), or the gap reason
// otherwise. The node is emitted even on a partial gather, so a bucket is never
// dropped from the graph because one of its reads failed.
func (c *StorageCollector) configureBucket(ctx context.Context, sink collect.Sink, name string) string {
	a := map[string]string{}
	gap := c.gatherBucket(ctx, sink, name, a)
	arn := "arn:aws:s3:::" + name
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: arn, Name: name, Attributes: pruneEmpty(a)})
	return gap
}

// gatherBucket issues the per-bucket reads, filling a with the recorded facts and
// returning a gap reason. Budget exhaustion returns immediately; a per-call denial
// or error is remembered as the gap and the remaining reads still run, so the node
// carries as much fact as could be gathered.
func (c *StorageCollector) gatherBucket(ctx context.Context, sink collect.Sink, name string, a map[string]string) string {
	bucket := &name
	gap := ""

	// Region first: it is recorded and selects the region for the reads below. A
	// bucket read against the wrong region is rejected by S3, so the region
	// override matters.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	region := ""
	if loc, err := c.api.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket}); err != nil {
		gap = c.callGap(err)
	} else {
		_ = sink.Evidence(c.evidence("GetBucketLocation", collect.Global, name, loc))
		region = normalizeRegion(string(loc.LocationConstraint))
		a["region"] = region
	}
	opt := regionOpt(region)

	// Public-access block (four flags), or absent.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if pab, err := c.api.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetPublicAccessBlock", region, name, pab))
		if p := pab.PublicAccessBlockConfiguration; p != nil {
			a["pab_block_public_acls"] = boolAttr(p.BlockPublicAcls)
			a["pab_ignore_public_acls"] = boolAttr(p.IgnorePublicAcls)
			a["pab_block_public_policy"] = boolAttr(p.BlockPublicPolicy)
			a["pab_restrict_public_buckets"] = boolAttr(p.RestrictPublicBuckets)
		}
	} else if isNotConfigured(err) {
		a["public_access_block"] = "none"
	} else {
		gap = c.callGap(err)
	}

	// Policy public-status (the provider's own IsPublic), or no policy.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if ps, err := c.api.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetBucketPolicyStatus", region, name, ps))
		if ps.PolicyStatus != nil {
			a["policy_is_public"] = boolAttr(ps.PolicyStatus.IsPublic)
		}
	} else if isNotConfigured(err) {
		a["bucket_policy"] = "none"
	} else {
		gap = c.callGap(err)
	}

	// ACL public grants (legacy public-access vector): record the permissions
	// granted to the public groups as facts, not a verdict.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if acl, err := c.api.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetBucketAcl", region, name, acl))
		mapACLGrants(a, acl)
	} else {
		gap = c.callGap(err)
	}

	// Default encryption, or absent.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if enc, err := c.api.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetBucketEncryption", region, name, enc))
		mapEncryption(a, enc)
	} else if isNotConfigured(err) {
		a["encryption"] = "none"
	} else {
		gap = c.callGap(err)
	}

	// Versioning (and MFA delete).
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if ver, err := c.api.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetBucketVersioning", region, name, ver))
		if s := string(ver.Status); s != "" {
			a["versioning"] = s
		} else {
			a["versioning"] = "Disabled"
		}
		if m := string(ver.MFADelete); m != "" {
			a["mfa_delete"] = m
		}
	} else {
		gap = c.callGap(err)
	}

	// Tags, or none.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if tag, err := c.api.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: bucket}, opt); err == nil {
		_ = sink.Evidence(c.evidence("GetBucketTagging", region, name, tag))
		for _, t := range tag.TagSet {
			if k := deref(t.Key); k != "" {
				a["tag:"+k] = deref(t.Value)
			}
		}
	} else if !isNotConfigured(err) {
		gap = c.callGap(err)
	}

	return gap
}

// mapACLGrants records the permissions granted to the public ACL groups (all
// users, and any authenticated AWS user) as facts. The "is public" conclusion is
// left to the rule engine.
func mapACLGrants(a map[string]string, acl *s3.GetBucketAclOutput) {
	const (
		allUsers  = "http://acs.amazonaws.com/groups/global/AllUsers"
		authUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	)
	for _, g := range acl.Grants {
		if g.Grantee == nil || g.Grantee.URI == nil {
			continue
		}
		switch *g.Grantee.URI {
		case allUsers:
			a["acl_all_users"] = appendPerm(a["acl_all_users"], string(g.Permission))
		case authUsers:
			a["acl_authenticated_users"] = appendPerm(a["acl_authenticated_users"], string(g.Permission))
		}
	}
}

// mapEncryption records the default-encryption algorithm and, for SSE-KMS, the
// key, from the first rule.
func mapEncryption(a map[string]string, enc *s3.GetBucketEncryptionOutput) {
	if enc.ServerSideEncryptionConfiguration == nil {
		return
	}
	for _, r := range enc.ServerSideEncryptionConfiguration.Rules {
		d := r.ApplyServerSideEncryptionByDefault
		if d == nil {
			continue
		}
		a["encryption"] = string(d.SSEAlgorithm)
		if d.KMSMasterKeyID != nil && *d.KMSMasterKeyID != "" {
			a["encryption_kms_key"] = *d.KMSMasterKeyID
		}
		return
	}
}

func appendPerm(existing, perm string) string {
	if perm == "" {
		return existing
	}
	if existing == "" {
		return perm
	}
	return existing + "," + perm
}

// normalizeRegion maps an S3 LocationConstraint to a region id. An empty
// constraint is the us-east-1 sentinel; the legacy "EU" alias is eu-west-1.
func normalizeRegion(loc string) string {
	switch loc {
	case "":
		return "us-east-1"
	case "EU":
		return "eu-west-1"
	default:
		return loc
	}
}

// regionOpt returns an S3 option that targets a bucket's region, or a no-op when
// the region is unknown (the read then uses the client's default region).
func regionOpt(region string) func(*s3.Options) {
	return func(o *s3.Options) {
		if region != "" {
			o.Region = region
		}
	}
}

// isNotConfigured reports the documented S3 responses for an absent sub-resource
// (no public-access block, no bucket policy, no default encryption, no tag set).
// These mean the protection is absent, which is a fact to record, not an
// access-control gap and not a pass.
func isNotConfigured(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchPublicAccessBlockConfiguration",
		"NoSuchBucketPolicy",
		"ServerSideEncryptionConfigurationNotFoundError",
		"NoSuchTagSet":
		return true
	}
	return false
}

// callGap classifies a per-bucket read error into a gap reason (never empty).
func (c *StorageCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *StorageCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one S3 read. The response
// carries no secret value or object content; it still passes through redaction as
// defence in depth. region is the read's region ("global" for ListBuckets) and
// resource is the bucket name, for provenance.
func (c *StorageCollector) evidence(operation, region, resource string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	if region == "" {
		region = collect.Global
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "s3", Operation: operation, Region: region,
		Scope:      collect.Scope{Account: c.account, Resource: resource},
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: s3APIVersion, Collector: storageCollectorID},
	}
}

// completeness classifies an S3 error into a completeness record with a redacted
// reason (used for the bucket-list read).
func (c *StorageCollector) completeness(service, region, resource string, collected int, err error) collect.Completeness {
	if region == "" {
		region = collect.Global
	}
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{
		Service: service, Region: region, Scope: collect.Scope{Account: c.account, Resource: resource},
		Status: status, Collected: collected, Reason: redact.String(err.Error()),
	}
}

// boolAttr renders an optional bool as "true"/"false", or "" when unset.
func boolAttr(b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return "true"
	}
	return "false"
}

// pruneEmpty drops empty-valued attributes, returning nil when none remain.
func pruneEmpty(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
