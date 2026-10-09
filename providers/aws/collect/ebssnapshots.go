package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const ebsSnapshotCollectorID = "collector:aws.ec2.ebsSnapshots"

const (
	svcEBSSnapshots     = "ec2.snapshots"
	svcEBSSnapshotAttrs = "ec2.snapshotAttributes"
)

// ebsSnapshotAPI is the read-only EC2 surface for EBS snapshots: list the account's
// own snapshots, then read each one's createVolumePermission attribute to detect a
// public share (EC2 service authorization reference, verified 2026-10-04). Neither
// returns volume data; the attribute read returns only who the snapshot is shared
// with.
type ebsSnapshotAPI interface {
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSnapshotAttribute(context.Context, *ec2.DescribeSnapshotAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error)
}

// EBSSnapshotCollector reads the account's own EBS snapshots in each region and,
// for each, whether it is shared publicly (createVolumePermission group "all"). A
// publicly shared snapshot can be copied or restored into a volume by any AWS
// account, so it is a direct data-exposure risk the storage and network collectors
// do not see. The list call does not report the share, so a per-snapshot attribute
// pass reads it; that pass has its own completeness, so a snapshot whose attribute
// could not be read is public_shared "unknown", never a silent "false".
type EBSSnapshotCollector struct {
	account string
	api     ebsSnapshotAPI
	budget  *collect.Budget
	regions []string
}

// NewEBSSnapshotCollector builds the collector with a read-only EC2 client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewEBSSnapshotCollector(account string, cfg awssdk.Config, budget *collect.Budget) *EBSSnapshotCollector {
	return &EBSSnapshotCollector{account: account, api: ec2.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

func newEBSSnapshotCollector(account string, api ebsSnapshotAPI, regions []string) *EBSSnapshotCollector {
	return &EBSSnapshotCollector{account: account, api: api, regions: regions}
}

func (c *EBSSnapshotCollector) ID() string               { return ebsSnapshotCollectorID }
func (c *EBSSnapshotCollector) Provider() model.Provider { return model.AWS }

func ebsSnapshotRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: ebsSnapshotCollectorID}
	}
	return []permissions.Requirement{
		req("ec2:DescribeSnapshots"),
		req("ec2:DescribeSnapshotAttribute"),
	}
}

func init() {
	for _, r := range ebsSnapshotRequirements() {
		permissions.Declare(r)
	}
}

func (c *EBSSnapshotCollector) Requirements() []permissions.Requirement {
	return ebsSnapshotRequirements()
}

// Collect enumerates each region's own snapshots and their public-share attribute,
// recording one completeness per (service, region). Budget exhaustion marks the
// unreached regions Partial for both services.
func (c *EBSSnapshotCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			_ = sink.Complete(c.gap(svcEBSSnapshots, region, collect.Partial, 0, "budget exhausted"))
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, 0, "budget exhausted"))
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

func (c *EBSSnapshotCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var snaps []ec2types.Snapshot
	in := &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcEBSSnapshots, region, collect.Partial, len(snaps), "cancelled"))
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, 0, "cancelled"))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.gap(svcEBSSnapshots, region, collect.Partial, len(snaps), "budget exhausted"))
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, 0, "budget exhausted"))
			return true, nil
		}
		out, err := c.api.DescribeSnapshots(ctx, in, inRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.gap(svcEBSSnapshots, region, collect.Partial, len(snaps), "cancelled"))
				_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, 0, "cancelled"))
				return false, cerr
			}
			// The list failed: record its gap. Nothing to check, so the attribute
			// pass is an honest Complete/0.
			_ = sink.Complete(c.completeness(svcEBSSnapshots, region, len(snaps), err))
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Complete, 0, ""))
			if isRegionNotEnabled(err) || isDenied(err) || isThrottle(err) || isTransport(err) {
				return false, nil
			}
			return false, err
		}
		_ = sink.Evidence(c.evidence("DescribeSnapshots", region, out))
		snaps = append(snaps, out.Snapshots...)
		if out.NextToken == nil || *out.NextToken == "" {
			_ = sink.Complete(c.gap(svcEBSSnapshots, region, collect.Complete, len(snaps), ""))
			break
		}
		in.NextToken = out.NextToken
	}
	return c.snapshotAttributes(ctx, sink, region, snaps)
}

// snapshotAttributes reads each snapshot's createVolumePermission and records the
// public_shared fact. A snapshot whose attribute read failed is public_shared
// "unknown"; the pass reason carries the first failure.
func (c *EBSSnapshotCollector) snapshotAttributes(ctx context.Context, sink collect.Sink, region string, snaps []ec2types.Snapshot) (bool, error) {
	checked := 0
	reason := ""
	for i, s := range snaps {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, checked, "cancelled"))
			return false, err
		}
		if !c.budget.Spend() {
			for _, rest := range snaps[i:] {
				c.emit(sink, region, rest, "unknown")
			}
			_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, collect.Partial, checked, "budget exhausted"))
			return true, nil
		}
		public := "unknown"
		res, err := c.api.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: s.SnapshotId, Attribute: ec2types.SnapshotAttributeNameCreateVolumePermission,
		}, inRegion(region))
		if err != nil {
			if reason == "" {
				reason = c.callReason(err)
			}
		} else {
			_ = sink.Evidence(c.evidence("DescribeSnapshotAttribute", region, res))
			public = strconv.FormatBool(createVolumePermissionPublic(res.CreateVolumePermissions))
			checked++
		}
		c.emit(sink, region, s, public)
	}
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(c.gap(svcEBSSnapshotAttrs, region, status, checked, reason))
	return false, nil
}

// createVolumePermissionPublic reports whether any create-volume permission grants
// the "all" group, i.e. the snapshot is public.
func createVolumePermissionPublic(perms []ec2types.CreateVolumePermission) bool {
	for _, p := range perms {
		if p.Group == ec2types.PermissionGroupAll {
			return true
		}
	}
	return false
}

func (c *EBSSnapshotCollector) emit(sink collect.Sink, region string, s ec2types.Snapshot, public string) {
	id, owner := deref(s.SnapshotId), deref(s.OwnerId)
	if id == "" {
		return
	}
	a := base("ebs-snapshot", id, region, owner)
	a["public_shared"] = public
	a["state"] = string(s.State)
	a["encrypted"] = boolAttr(s.Encrypted)
	a["volume_id"] = deref(s.VolumeId)
	if s.VolumeSize != nil {
		a["volume_size_gib"] = strconv.FormatInt(int64(*s.VolumeSize), 10)
	}
	a["storage_tier"] = string(s.StorageTier)
	name := tagAttrs(a, s.Tags)
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: c.ec2ARN(region, owner, "snapshot", id),
		Name: firstNonEmpty(name, id), Attributes: pruneEmpty(a)})
}

func (c *EBSSnapshotCollector) ec2ARN(region, owner, resourceType, id string) string {
	if owner == "" {
		owner = c.account
	}
	return "arn:aws:ec2:" + region + ":" + owner + ":" + resourceType + "/" + id
}

func (c *EBSSnapshotCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

func (c *EBSSnapshotCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "ec2", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: ec2APIVersion, Collector: ebsSnapshotCollectorID},
	}
}

func (c *EBSSnapshotCollector) gap(service, region string, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: collected, Reason: reason}
}

func (c *EBSSnapshotCollector) completeness(service, region string, collected int, err error) collect.Completeness {
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
	return c.gap(service, region, status, collected, reason)
}

// callReason classifies a per-snapshot attribute-read failure for the pass reason.
func (c *EBSSnapshotCollector) callReason(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	case isTransport(err):
		return "unreachable"
	}
	return redact.String(err.Error())
}
