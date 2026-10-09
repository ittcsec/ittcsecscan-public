package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	smithy "github.com/aws/smithy-go"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// kmsCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const kmsCollectorID = "collector:aws.kms"

// kmsAPIVersion is the KMS API version, recorded as evidence provenance.
const kmsAPIVersion = "2014-11-01"

// The completeness service names this collector records, per region: the alias
// listing, the key listing, and the per-key detail pass (describe, policy,
// rotation, tags), following the S3 list-plus-detail shape.
const (
	svcKMSAliases    = "kms.aliases"
	svcKMSKeys       = "kms.keys"
	svcKMSKeyDetails = "kms.keyDetails"
)

// kmsAPI is the read-only KMS surface the collector uses: three List reads and
// three Read reads (KMS service authorization reference, verified 2026-09-20). None
// performs a cryptographic operation or returns key material; GetKeyPolicy returns
// the key's resource policy document, which is an authorization policy, not a
// secret. Each call takes optFns so the collector targets one declared region.
type kmsAPI interface {
	ListAliases(context.Context, *kms.ListAliasesInput, ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
}

// KMSCollector reads the account's KMS keys in each declared region (ADR-0019 §1):
// every key's metadata, resource policy, rotation status, and tags, with aliases
// resolved for naming. It is a sensitive-asset collector like S3 and RDS, and its
// key nodes are keyed by key ARN so the kms_key_id references the S3 and RDS
// collectors already record resolve directly onto them.
//
// Per ADR-0019 §3 it emits nodes and attributes only, no edges, and records the raw
// key-policy document as a fact without judging whether it is public or grants
// cross-account access: that evaluation (principal expansion, org conditions) is
// genuinely complex and belongs to the rule engine, not to evidence collection. The
// collector never creates a security fact, only records the provider's own.
type KMSCollector struct {
	account string
	api     kmsAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewKMSCollector builds the collector with a read-only KMS client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewKMSCollector(account string, cfg awssdk.Config, budget *collect.Budget) *KMSCollector {
	return &KMSCollector{account: account, api: kms.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newKMSCollector is the injectable constructor tests use with a stub API and an
// explicit region list. It has no budget (unlimited).
func newKMSCollector(account string, api kmsAPI, regions []string) *KMSCollector {
	return &KMSCollector{account: account, api: api, regions: regions}
}

func (c *KMSCollector) ID() string               { return kmsCollectorID }
func (c *KMSCollector) Provider() model.Provider { return model.AWS }

// kmsRequirements are the read-only permissions this collector needs. Each maps to
// a kms: action of the same name (KMS service authorization reference, verified
// 2026-09-20). Registered at init so the templates reconcile against real code
// (ADR-0016).
func kmsRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: kmsCollectorID}
	}
	return []permissions.Requirement{
		req("kms:ListAliases"),
		req("kms:ListKeys"),
		req("kms:DescribeKey"),
		req("kms:GetKeyPolicy"),
		req("kms:GetKeyRotationStatus"),
		req("kms:ListResourceTags"),
	}
}

func init() {
	for _, r := range kmsRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *KMSCollector) Requirements() []permissions.Requirement { return kmsRequirements() }

// kmsServices lists every completeness service, in order, for marking the resources
// not reached once the shared budget is exhausted.
func kmsServices() []string {
	return []string{svcKMSAliases, svcKMSKeys, svcKMSKeyDetails}
}

// Collect enumerates aliases and keys in every declared region, sequentially
// (ADR-0019 §1), recording one completeness record per (service, region). A denied,
// throttled, not-enabled, or unreachable read is a represented gap and the other
// services and regions still run; budget exhaustion marks every (service, region)
// not yet reached Partial "budget exhausted". An unexpected error is Errored, the
// rest still run, and the errors surface.
func (c *KMSCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			for _, s := range kmsServices() {
				_ = sink.Complete(c.budgetGap(s, region))
			}
			continue
		}
		budgetOut, err := c.collectRegion(ctx, sink, region)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, err)
		}
		exhausted = budgetOut
	}
	return errors.Join(errs...)
}

// collectRegion resolves aliases (for naming) then enumerates and details the keys
// for one region.
func (c *KMSCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var errs []error

	aliases, bo, err := c.collectAliases(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcKMSKeys, svcKMSKeyDetails)
		return true, errors.Join(errs...)
	}

	bo, err = c.collectKeys(ctx, sink, region, aliases)
	errs = appendErr(errs, err)
	return bo, errors.Join(errs...)
}

// collectAliases paginates ListAliases and returns a key-id to alias-name map (the
// first alias seen for a key wins), recording the svcKMSAliases completeness.
func (c *KMSCollector) collectAliases(ctx context.Context, sink collect.Sink, region string) (map[string]string, bool, error) {
	aliases := map[string]string{}
	in := &kms.ListAliasesInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcKMSAliases, region, len(aliases)))
			return aliases, false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcKMSAliases, region))
			return aliases, true, nil
		}
		out, err := c.api.ListAliases(ctx, in, kmsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcKMSAliases, region, len(aliases)))
				return aliases, false, cerr
			}
			return aliases, false, c.listError(sink, svcKMSAliases, region, len(aliases), err)
		}
		_ = sink.Evidence(c.evidence("ListAliases", region, out))
		for _, a := range out.Aliases {
			key := deref(a.TargetKeyId)
			if key == "" {
				continue
			}
			if _, ok := aliases[key]; !ok {
				aliases[key] = deref(a.AliasName)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			_ = sink.Complete(c.completeCount(svcKMSAliases, region, len(aliases)))
			return aliases, false, nil
		}
		in.Marker = out.NextMarker
	}
}

// keyRef is a key to detail: its id and ARN from the list entry.
type keyRef struct{ id, arn string }

// collectKeys paginates ListKeys, records svcKMSKeys, then details each key and
// records svcKMSKeyDetails.
func (c *KMSCollector) collectKeys(ctx context.Context, sink collect.Sink, region string, aliases map[string]string) (bool, error) {
	var keys []keyRef
	in := &kms.ListKeysInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcKMSKeys, region, len(keys)))
			_ = sink.Complete(c.cancelledGap(svcKMSKeyDetails, region, 0))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcKMSKeys, region))
			_ = sink.Complete(c.budgetGap(svcKMSKeyDetails, region))
			return true, nil
		}
		out, err := c.api.ListKeys(ctx, in, kmsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcKMSKeys, region, len(keys)))
				_ = sink.Complete(c.cancelledGap(svcKMSKeyDetails, region, 0))
				return false, cerr
			}
			listErr := c.listError(sink, svcKMSKeys, region, len(keys), err)
			_ = sink.Complete(c.completeCount(svcKMSKeyDetails, region, 0))
			return false, listErr
		}
		_ = sink.Evidence(c.evidence("ListKeys", region, out))
		for _, k := range out.Keys {
			if id := deref(k.KeyId); id != "" {
				keys = append(keys, keyRef{id: id, arn: deref(k.KeyArn)})
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			_ = sink.Complete(c.completeCount(svcKMSKeys, region, len(keys)))
			break
		}
		in.Marker = out.NextMarker
	}
	return c.detailKeys(ctx, sink, region, keys, aliases)
}

// detailKeys gathers each key's metadata, policy, rotation, and tags, emits the
// node, and records the svcKMSKeyDetails completeness. A per-key gap does not drop
// the node; budget exhaustion stops the pass.
func (c *KMSCollector) detailKeys(ctx context.Context, sink collect.Sink, region string, keys []keyRef, aliases map[string]string) (bool, error) {
	done := 0
	reason := ""
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcKMSKeyDetails, region, done))
			return false, err
		}
		gap := c.detailKey(ctx, sink, region, k, aliases)
		if gap == "budget exhausted" {
			_ = sink.Complete(c.budgetGap(svcKMSKeyDetails, region))
			return true, nil
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
	_ = sink.Complete(collect.Completeness{Service: svcKMSKeyDetails, Region: region, Scope: c.scope(), Status: status, Collected: done, Reason: reason})
	return false, nil
}

// detailKey gathers one key's facts and emits the node once (keyed by ARN). It
// returns "" when every read completed, "budget exhausted" to stop the pass, or a
// gap reason. The node is emitted even on a partial gather so a key is never dropped
// from the graph because one read failed.
func (c *KMSCollector) detailKey(ctx context.Context, sink collect.Sink, region string, k keyRef, aliases map[string]string) string {
	a := map[string]string{"region": region}
	gap := ""
	arn := k.arn

	// Metadata: manager, state, spec, usage, origin, multi-region.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if dk, err := c.api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &k.id}, kmsInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidence("DescribeKey", region, dk))
		if m := dk.KeyMetadata; m != nil {
			if v := deref(m.Arn); v != "" {
				arn = v
			}
			a["key_manager"] = string(m.KeyManager)
			a["key_state"] = string(m.KeyState)
			a["key_spec"] = string(m.KeySpec)
			a["key_usage"] = string(m.KeyUsage)
			a["origin"] = string(m.Origin)
			a["enabled"] = strconv.FormatBool(m.Enabled)
			a["multi_region"] = boolAttr(m.MultiRegion)
			a["description"] = deref(m.Description)
		}
	} else {
		gap = c.callGap(err)
	}

	// Resource policy: recorded as a raw fact, never judged public here.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if pol, err := c.api.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: &k.id}, kmsInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidence("GetKeyPolicy", region, pol))
		a["key_policy"] = redact.String(deref(pol.Policy))
	} else {
		gap = c.callGap(err)
	}

	// Rotation: a definitive "not supported for this key type" is a recorded fact
	// (raw provider signal), like an absent S3 sub-resource; an invalid key state or
	// a denial is a gap.
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if rot, err := c.api.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &k.id}, kmsInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidence("GetKeyRotationStatus", region, rot))
		a["rotation_enabled"] = strconv.FormatBool(rot.KeyRotationEnabled)
		a["rotation_period_days"] = intAttr(rot.RotationPeriodInDays)
	} else if isUnsupportedForKey(err) {
		a["rotation_enabled"] = "not_applicable"
	} else {
		gap = c.callGap(err)
	}

	// Tags (ListResourceTags returns up to the full tag set in one page).
	if !c.budget.Spend() {
		return "budget exhausted"
	}
	if tg, err := c.api.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: &k.id}, kmsInRegion(region)); err == nil {
		_ = sink.Evidence(c.evidence("ListResourceTags", region, tg))
		for _, t := range tg.Tags {
			if key := deref(t.TagKey); key != "" {
				a["tag:"+key] = deref(t.TagValue)
			}
		}
	} else {
		gap = c.callGap(err)
	}

	name := aliases[k.id]
	if name == "" {
		name = k.id
	}
	_ = sink.Node(collect.Node{Type: model.NodeControl, NativeID: arn, Name: name, Attributes: pruneEmpty(a)})
	return gap
}

// kmsInRegion targets one KMS call at a declared region.
func kmsInRegion(region string) func(*kms.Options) {
	return func(o *kms.Options) { o.Region = region }
}

// isUnsupportedForKey reports the definitive "this operation does not apply to this
// key" signal (an asymmetric or HMAC key has no rotation to report). It is a
// recorded fact, not a collection gap.
func isUnsupportedForKey(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	return api.ErrorCode() == "UnsupportedOperationException"
}

// isKeyStateGap reports a key whose state prevents the read (disabled or pending
// deletion): a real account state, recorded as a gap, not an error and not a pass.
func isKeyStateGap(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "KMSInvalidStateException", "DisabledException":
		return true
	}
	return false
}

// listError records a list read's error as a completeness gap and returns the error
// to surface only when it is unexpected (Errored).
func (c *KMSCollector) listError(sink collect.Sink, service, region string, collected int, err error) error {
	comp := c.completeness(service, region, collected, err)
	_ = sink.Complete(comp)
	if comp.Status == collect.Errored {
		return err
	}
	return nil
}

// completeness classifies a KMS list error into a completeness record. A not-enabled
// region is Unsupported, a denial Denied, a throttle Partial, a transport failure a
// non-fatal Partial "unreachable" (ADR-0018 §4), anything else Errored.
func (c *KMSCollector) completeness(service, region string, collected int, err error) collect.Completeness {
	status := collect.Errored
	reason := redact.String(err.Error())
	switch {
	case isRegionNotEnabled(err):
		status = collect.Unsupported
		reason = "region not enabled"
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	case isTransport(err):
		status = collect.Partial
		reason = "unreachable"
	}
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

func (c *KMSCollector) completeCount(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: collected}
}

func (c *KMSCollector) budgetGap(service, region string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"}
}

func (c *KMSCollector) cancelledGap(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: collected, Reason: "cancelled"}
}

func (c *KMSCollector) markBudget(sink collect.Sink, region string, services ...string) {
	for _, s := range services {
		_ = sink.Complete(c.budgetGap(s, region))
	}
}

// callGap classifies a per-key read error into a gap reason (never empty). An
// invalid key state (disabled, pending deletion) is its own honest gap.
func (c *KMSCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isKeyStateGap(err):
		return "invalid key state"
	}
	return redact.String(err.Error())
}

func (c *KMSCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one KMS read. A key policy is
// an authorization document, not key material, but it still passes through redaction
// as defence in depth.
func (c *KMSCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "kms", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: kmsAPIVersion, Collector: kmsCollectorID},
	}
}
