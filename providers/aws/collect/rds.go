package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// rdsCollectorID is the stable id this collector is credited with in the
// permission templates and evidence provenance.
const rdsCollectorID = "collector:aws.rds"

// rdsAPIVersion is the RDS API version, recorded as evidence provenance.
const rdsAPIVersion = "2014-10-31"

// The completeness service names this collector records, per region. The two
// *Attributes services are companion records for the per-snapshot public-share
// check, kept distinct (like s3.bucketConfig is distinct from s3.buckets) so an
// unchecked snapshot stays honestly separate from a confirmed-private one.
const (
	svcDBInstances        = "rds.dbInstances"
	svcDBClusters         = "rds.dbClusters"
	svcDBSnapshots        = "rds.dbSnapshots"
	svcSnapshotAttrs      = "rds.snapshotAttributes"
	svcDBClusterSnapshots = "rds.dbClusterSnapshots"
	svcClusterSnapAttrs   = "rds.clusterSnapshotAttributes"
)

// rdsAPI is the read-only RDS surface the collector uses: four Describe reads at
// the List level and two *Attributes reads at the Read level (RDS service
// authorization reference, verified 2026-09-20). None modifies anything or returns
// a secret value. Each call takes optFns so the collector targets one declared
// region at a time.
type rdsAPI interface {
	DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBSnapshots(context.Context, *rds.DescribeDBSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeDBSnapshotAttributes(context.Context, *rds.DescribeDBSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error)
	DescribeDBClusterSnapshots(context.Context, *rds.DescribeDBClusterSnapshotsInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBClusterSnapshotAttributes(context.Context, *rds.DescribeDBClusterSnapshotAttributesInput, ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error)
}

// RDSCollector reads the account's RDS databases in each declared region
// (ADR-0019 §1): DB instances, DB clusters, and their manual and automated
// snapshots. It is a sensitive-asset collector like the S3 one, and records the
// provider's own facts without synthesizing an "is exposed" verdict: whether a
// publicly accessible instance or a publicly shared snapshot is actually a finding
// belongs to the rule and reachability engines. Per ADR-0019 §3 it emits nodes and
// attributes only, no edges; cross-references (kms_key_id, vpc_security_group_ids,
// VPC and subnet group, and a snapshot's source) are recorded as id facts so those
// engines can join them later (kms_key_id lines up with the coming KMS collector).
//
// Public snapshots are the headline risk: a manual snapshot shared with "all" can
// be copied or restored by any AWS account. The list call does not report that, so
// for each manual snapshot the collector reads DescribeDB(Cluster)SnapshotAttributes
// and records the restore=all fact. That per-snapshot pass has its own completeness
// record so a snapshot whose attributes could not be read is honestly distinct from
// one confirmed private (verified against the RDS API reference, 2026-09-20).
type RDSCollector struct {
	account string
	api     rdsAPI
	budget  *collect.Budget // the scan's shared call cap; nil is unlimited
	regions []string
}

// NewRDSCollector builds the collector with a read-only RDS client from the
// adapter's resolved config (ADR-0018 §3), over the declared region set.
func NewRDSCollector(account string, cfg awssdk.Config, budget *collect.Budget) *RDSCollector {
	return &RDSCollector{account: account, api: rds.NewFromConfig(cfg), budget: budget, regions: defaultRegions}
}

// newRDSCollector is the injectable constructor tests use with a stub API and an
// explicit region list. It has no budget (unlimited).
func newRDSCollector(account string, api rdsAPI, regions []string) *RDSCollector {
	return &RDSCollector{account: account, api: api, regions: regions}
}

func (c *RDSCollector) ID() string               { return rdsCollectorID }
func (c *RDSCollector) Provider() model.Provider { return model.AWS }

// rdsRequirements are the read-only permissions this collector needs. Each maps to
// an rds: action of the same name (RDS service authorization reference, verified
// 2026-09-20): the four Describe reads at List level and the two *Attributes reads
// at Read level. Registered at init so the templates reconcile against real code
// (ADR-0016).
func rdsRequirements() []permissions.Requirement {
	req := func(p string) permissions.Requirement {
		return permissions.Requirement{Provider: model.AWS, Profile: permissions.Discovery, Permission: p, By: rdsCollectorID}
	}
	return []permissions.Requirement{
		req("rds:DescribeDBInstances"),
		req("rds:DescribeDBClusters"),
		req("rds:DescribeDBSnapshots"),
		req("rds:DescribeDBSnapshotAttributes"),
		req("rds:DescribeDBClusterSnapshots"),
		req("rds:DescribeDBClusterSnapshotAttributes"),
	}
}

func init() {
	for _, r := range rdsRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *RDSCollector) Requirements() []permissions.Requirement { return rdsRequirements() }

// allServices lists every completeness service, in order, for marking the resources
// not reached once the shared budget is exhausted.
func allServices() []string {
	return []string{svcDBInstances, svcDBClusters, svcDBSnapshots, svcSnapshotAttrs, svcDBClusterSnapshots, svcClusterSnapAttrs}
}

// Collect enumerates instances, clusters, and snapshots in every declared region,
// sequentially (ADR-0019 §1), recording one completeness record per (service,
// region). A denied, throttled, not-enabled, or unreachable read is a represented
// gap and the other services and regions still run; budget exhaustion marks every
// (service, region) not yet reached Partial "budget exhausted". An unexpected error
// is Errored, the rest still run, and the errors surface.
func (c *RDSCollector) Collect(ctx context.Context, sink collect.Sink) error {
	var errs []error
	exhausted := false
	for _, region := range c.regions {
		if exhausted {
			for _, s := range allServices() {
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

// collectRegion runs the four enumerations for one region in order. On budget
// exhaustion the running enumeration records its own services and this function
// marks the services after it (in this region) Partial "budget exhausted", then
// reports the budget is out so the caller marks later regions.
func (c *RDSCollector) collectRegion(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var errs []error

	bo, err := c.collectInstances(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcDBClusters, svcDBSnapshots, svcSnapshotAttrs, svcDBClusterSnapshots, svcClusterSnapAttrs)
		return true, errors.Join(errs...)
	}

	bo, err = c.collectClusters(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcDBSnapshots, svcSnapshotAttrs, svcDBClusterSnapshots, svcClusterSnapAttrs)
		return true, errors.Join(errs...)
	}

	bo, err = c.collectSnapshots(ctx, sink, region)
	errs = appendErr(errs, err)
	if bo {
		c.markBudget(sink, region, svcDBClusterSnapshots, svcClusterSnapAttrs)
		return true, errors.Join(errs...)
	}

	bo, err = c.collectClusterSnapshots(ctx, sink, region)
	errs = appendErr(errs, err)
	return bo, errors.Join(errs...)
}

// collectInstances paginates DescribeDBInstances for one region, emitting a
// data-store node per instance, and records the svcDBInstances completeness.
func (c *RDSCollector) collectInstances(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	count := 0
	in := &rds.DescribeDBInstancesInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcDBInstances, region, count))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcDBInstances, region))
			return true, nil
		}
		out, err := c.api.DescribeDBInstances(ctx, in, rdsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcDBInstances, region, count))
				return false, cerr
			}
			return false, c.listError(sink, svcDBInstances, region, count, err)
		}
		_ = sink.Evidence(c.evidence("DescribeDBInstances", region, out))
		for _, i := range out.DBInstances {
			c.mapInstance(sink, region, i)
			count++
		}
		if out.Marker == nil || *out.Marker == "" {
			_ = sink.Complete(c.completeCount(svcDBInstances, region, count))
			return false, nil
		}
		in.Marker = out.Marker
	}
}

// collectClusters paginates DescribeDBClusters for one region.
func (c *RDSCollector) collectClusters(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	count := 0
	in := &rds.DescribeDBClustersInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcDBClusters, region, count))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcDBClusters, region))
			return true, nil
		}
		out, err := c.api.DescribeDBClusters(ctx, in, rdsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcDBClusters, region, count))
				return false, cerr
			}
			return false, c.listError(sink, svcDBClusters, region, count, err)
		}
		_ = sink.Evidence(c.evidence("DescribeDBClusters", region, out))
		for _, cl := range out.DBClusters {
			c.mapCluster(sink, region, cl)
			count++
		}
		if out.Marker == nil || *out.Marker == "" {
			_ = sink.Complete(c.completeCount(svcDBClusters, region, count))
			return false, nil
		}
		in.Marker = out.Marker
	}
}

// collectSnapshots lists DB snapshots then, for each manual one, reads its restore
// attribute to detect a public share. It records two completeness records: the list
// (svcDBSnapshots) and the per-snapshot attribute pass (svcSnapshotAttrs). A manual
// snapshot whose attributes could not be read is emitted with public_shared
// "unknown", never silently "false".
func (c *RDSCollector) collectSnapshots(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var snaps []rdstypes.DBSnapshot
	in := &rds.DescribeDBSnapshotsInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcDBSnapshots, region, len(snaps)))
			_ = sink.Complete(c.cancelledGap(svcSnapshotAttrs, region, 0))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcDBSnapshots, region))
			_ = sink.Complete(c.budgetGap(svcSnapshotAttrs, region))
			return true, nil
		}
		out, err := c.api.DescribeDBSnapshots(ctx, in, rdsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcDBSnapshots, region, len(snaps)))
				_ = sink.Complete(c.cancelledGap(svcSnapshotAttrs, region, 0))
				return false, cerr
			}
			// The list failed: record its gap. There is nothing to check, so the
			// attribute pass is an honest Complete/0.
			listErr := c.listError(sink, svcDBSnapshots, region, len(snaps), err)
			_ = sink.Complete(c.completeCount(svcSnapshotAttrs, region, 0))
			return false, listErr
		}
		_ = sink.Evidence(c.evidence("DescribeDBSnapshots", region, out))
		snaps = append(snaps, out.DBSnapshots...)
		if out.Marker == nil || *out.Marker == "" {
			_ = sink.Complete(c.completeCount(svcDBSnapshots, region, len(snaps)))
			break
		}
		in.Marker = out.Marker
	}
	return c.snapshotAttributes(ctx, sink, region, snaps)
}

// snapshotAttributes runs the per-snapshot public-share check and records the
// svcSnapshotAttrs completeness. Only manual snapshots can be shared; an automated
// snapshot is recorded public_shared "false" with no call.
func (c *RDSCollector) snapshotAttributes(ctx context.Context, sink collect.Sink, region string, snaps []rdstypes.DBSnapshot) (bool, error) {
	checked := 0
	reason := ""
	for i, s := range snaps {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcSnapshotAttrs, region, checked))
			return false, err
		}
		if deref(s.SnapshotType) != "manual" {
			c.mapSnapshot(sink, region, s, "false")
			continue
		}
		if !c.budget.Spend() {
			for _, rest := range snaps[i:] {
				c.mapSnapshot(sink, region, rest, "unknown")
			}
			_ = sink.Complete(c.budgetGap(svcSnapshotAttrs, region))
			return true, nil
		}
		public := "unknown"
		res, err := c.api.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{DBSnapshotIdentifier: s.DBSnapshotIdentifier}, rdsInRegion(region))
		if err != nil {
			if reason == "" {
				reason = c.callGap(err)
			}
		} else {
			_ = sink.Evidence(c.evidence("DescribeDBSnapshotAttributes", region, res))
			public = attrPublic(attrList(res.DBSnapshotAttributesResult))
			checked++
		}
		c.mapSnapshot(sink, region, s, public)
	}
	c.completeAttrs(sink, svcSnapshotAttrs, region, checked, reason)
	return false, nil
}

// collectClusterSnapshots is the cluster-snapshot counterpart of collectSnapshots.
func (c *RDSCollector) collectClusterSnapshots(ctx context.Context, sink collect.Sink, region string) (bool, error) {
	var snaps []rdstypes.DBClusterSnapshot
	in := &rds.DescribeDBClusterSnapshotsInput{}
	for {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcDBClusterSnapshots, region, len(snaps)))
			_ = sink.Complete(c.cancelledGap(svcClusterSnapAttrs, region, 0))
			return false, err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(c.budgetGap(svcDBClusterSnapshots, region))
			_ = sink.Complete(c.budgetGap(svcClusterSnapAttrs, region))
			return true, nil
		}
		out, err := c.api.DescribeDBClusterSnapshots(ctx, in, rdsInRegion(region))
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				_ = sink.Complete(c.cancelledGap(svcDBClusterSnapshots, region, len(snaps)))
				_ = sink.Complete(c.cancelledGap(svcClusterSnapAttrs, region, 0))
				return false, cerr
			}
			listErr := c.listError(sink, svcDBClusterSnapshots, region, len(snaps), err)
			_ = sink.Complete(c.completeCount(svcClusterSnapAttrs, region, 0))
			return false, listErr
		}
		_ = sink.Evidence(c.evidence("DescribeDBClusterSnapshots", region, out))
		snaps = append(snaps, out.DBClusterSnapshots...)
		if out.Marker == nil || *out.Marker == "" {
			_ = sink.Complete(c.completeCount(svcDBClusterSnapshots, region, len(snaps)))
			break
		}
		in.Marker = out.Marker
	}
	return c.clusterSnapshotAttributes(ctx, sink, region, snaps)
}

func (c *RDSCollector) clusterSnapshotAttributes(ctx context.Context, sink collect.Sink, region string, snaps []rdstypes.DBClusterSnapshot) (bool, error) {
	checked := 0
	reason := ""
	for i, s := range snaps {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(c.cancelledGap(svcClusterSnapAttrs, region, checked))
			return false, err
		}
		if deref(s.SnapshotType) != "manual" {
			c.mapClusterSnapshot(sink, region, s, "false")
			continue
		}
		if !c.budget.Spend() {
			for _, rest := range snaps[i:] {
				c.mapClusterSnapshot(sink, region, rest, "unknown")
			}
			_ = sink.Complete(c.budgetGap(svcClusterSnapAttrs, region))
			return true, nil
		}
		public := "unknown"
		res, err := c.api.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{DBClusterSnapshotIdentifier: s.DBClusterSnapshotIdentifier}, rdsInRegion(region))
		if err != nil {
			if reason == "" {
				reason = c.callGap(err)
			}
		} else {
			_ = sink.Evidence(c.evidence("DescribeDBClusterSnapshotAttributes", region, res))
			public = attrPublic(clusterAttrList(res.DBClusterSnapshotAttributesResult))
			checked++
		}
		c.mapClusterSnapshot(sink, region, s, public)
	}
	c.completeAttrs(sink, svcClusterSnapAttrs, region, checked, reason)
	return false, nil
}

func (c *RDSCollector) mapInstance(sink collect.Sink, region string, i rdstypes.DBInstance) {
	arn := deref(i.DBInstanceArn)
	if arn == "" {
		return
	}
	a := map[string]string{
		"rds_type":                            "db_instance",
		"engine":                              deref(i.Engine),
		"engine_version":                      deref(i.EngineVersion),
		"status":                              deref(i.DBInstanceStatus),
		"instance_class":                      deref(i.DBInstanceClass),
		"publicly_accessible":                 boolAttr(i.PubliclyAccessible),
		"storage_encrypted":                   boolAttr(i.StorageEncrypted),
		"kms_key_id":                          deref(i.KmsKeyId),
		"iam_database_authentication_enabled": boolAttr(i.IAMDatabaseAuthenticationEnabled),
		"deletion_protection":                 boolAttr(i.DeletionProtection),
		"multi_az":                            boolAttr(i.MultiAZ),
		"backup_retention_days":               intAttr(i.BackupRetentionPeriod),
		"allocated_storage_gb":                intAttr(i.AllocatedStorage),
		"storage_type":                        deref(i.StorageType),
		"availability_zone":                   deref(i.AvailabilityZone),
		"db_cluster_identifier":               deref(i.DBClusterIdentifier),
		"region":                              region,
	}
	if e := i.Endpoint; e != nil {
		a["endpoint_address"] = deref(e.Address)
		a["endpoint_port"] = intAttr(e.Port)
	}
	if g := i.DBSubnetGroup; g != nil {
		a["db_subnet_group"] = deref(g.DBSubnetGroupName)
		a["vpc_id"] = deref(g.VpcId)
	}
	a["vpc_security_group_ids"] = joinSorted(vpcSGIDs(i.VpcSecurityGroups))
	mapTagList(a, i.TagList)
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: arn, Name: deref(i.DBInstanceIdentifier), Attributes: pruneEmpty(a)})
}

func (c *RDSCollector) mapCluster(sink collect.Sink, region string, cl rdstypes.DBCluster) {
	arn := deref(cl.DBClusterArn)
	if arn == "" {
		return
	}
	a := map[string]string{
		"rds_type":                            "db_cluster",
		"engine":                              deref(cl.Engine),
		"engine_version":                      deref(cl.EngineVersion),
		"engine_mode":                         deref(cl.EngineMode),
		"status":                              deref(cl.Status),
		"publicly_accessible":                 boolAttr(cl.PubliclyAccessible),
		"storage_encrypted":                   boolAttr(cl.StorageEncrypted),
		"kms_key_id":                          deref(cl.KmsKeyId),
		"iam_database_authentication_enabled": boolAttr(cl.IAMDatabaseAuthenticationEnabled),
		"deletion_protection":                 boolAttr(cl.DeletionProtection),
		"backup_retention_days":               intAttr(cl.BackupRetentionPeriod),
		"endpoint_address":                    deref(cl.Endpoint),
		"reader_endpoint_address":             deref(cl.ReaderEndpoint),
		"endpoint_port":                       intAttr(cl.Port),
		"db_subnet_group":                     deref(cl.DBSubnetGroup),
		"region":                              region,
	}
	a["vpc_security_group_ids"] = joinSorted(vpcSGIDs(cl.VpcSecurityGroups))
	mapTagList(a, cl.TagList)
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: arn, Name: deref(cl.DBClusterIdentifier), Attributes: pruneEmpty(a)})
}

func (c *RDSCollector) mapSnapshot(sink collect.Sink, region string, s rdstypes.DBSnapshot, public string) {
	arn := deref(s.DBSnapshotArn)
	if arn == "" {
		return
	}
	a := map[string]string{
		"rds_type":           "db_snapshot",
		"engine":             deref(s.Engine),
		"status":             deref(s.Status),
		"encrypted":          boolAttr(s.Encrypted),
		"kms_key_id":         deref(s.KmsKeyId),
		"snapshot_type":      deref(s.SnapshotType),
		"source_db_instance": deref(s.DBInstanceIdentifier),
		"availability_zone":  deref(s.AvailabilityZone),
		"vpc_id":             deref(s.VpcId),
		"public_shared":      public,
		"region":             region,
	}
	mapTagList(a, s.TagList)
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: arn, Name: deref(s.DBSnapshotIdentifier), Attributes: pruneEmpty(a)})
}

func (c *RDSCollector) mapClusterSnapshot(sink collect.Sink, region string, s rdstypes.DBClusterSnapshot, public string) {
	arn := deref(s.DBClusterSnapshotArn)
	if arn == "" {
		return
	}
	a := map[string]string{
		"rds_type":          "db_cluster_snapshot",
		"engine":            deref(s.Engine),
		"status":            deref(s.Status),
		"encrypted":         boolAttr(s.StorageEncrypted),
		"kms_key_id":        deref(s.KmsKeyId),
		"snapshot_type":     deref(s.SnapshotType),
		"source_db_cluster": deref(s.DBClusterIdentifier),
		"vpc_id":            deref(s.VpcId),
		"public_shared":     public,
		"region":            region,
	}
	mapTagList(a, s.TagList)
	_ = sink.Node(collect.Node{Type: model.NodeDataStore, NativeID: arn, Name: deref(s.DBClusterSnapshotIdentifier), Attributes: pruneEmpty(a)})
}

// attrPublic reports "true" when the restore attribute lists "all" (the snapshot is
// public), else "false".
func attrPublic(attrs []rdstypes.DBSnapshotAttribute) string {
	for _, at := range attrs {
		if deref(at.AttributeName) != "restore" {
			continue
		}
		for _, v := range at.AttributeValues {
			if v == "all" {
				return "true"
			}
		}
	}
	return "false"
}

func attrList(r *rdstypes.DBSnapshotAttributesResult) []rdstypes.DBSnapshotAttribute {
	if r == nil {
		return nil
	}
	return r.DBSnapshotAttributes
}

// clusterAttrList adapts the cluster-snapshot attribute result to the shared
// DBSnapshotAttribute shape (identical name/value fields) so attrPublic serves both.
func clusterAttrList(r *rdstypes.DBClusterSnapshotAttributesResult) []rdstypes.DBSnapshotAttribute {
	if r == nil {
		return nil
	}
	out := make([]rdstypes.DBSnapshotAttribute, 0, len(r.DBClusterSnapshotAttributes))
	for _, at := range r.DBClusterSnapshotAttributes {
		out = append(out, rdstypes.DBSnapshotAttribute{AttributeName: at.AttributeName, AttributeValues: at.AttributeValues})
	}
	return out
}

func vpcSGIDs(ms []rdstypes.VpcSecurityGroupMembership) []string {
	var out []string
	for _, m := range ms {
		if id := deref(m.VpcSecurityGroupId); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func mapTagList(a map[string]string, tags []rdstypes.Tag) {
	for _, t := range tags {
		if k := deref(t.Key); k != "" {
			a["tag:"+k] = deref(t.Value)
		}
	}
}

// rdsInRegion targets one RDS call at a declared region.
func rdsInRegion(region string) func(*rds.Options) {
	return func(o *rds.Options) { o.Region = region }
}

// listError records a list read's error as a completeness gap and returns the error
// to surface only when it is unexpected (Errored). A denied, throttled,
// not-enabled, or unreachable read is a represented gap with no surfaced error.
func (c *RDSCollector) listError(sink collect.Sink, service, region string, collected int, err error) error {
	comp := c.completeness(service, region, collected, err)
	_ = sink.Complete(comp)
	if comp.Status == collect.Errored {
		return err
	}
	return nil
}

// completeness classifies an RDS error into a completeness record. A not-enabled
// region is Unsupported, a denial Denied, a throttle Partial, a transport failure a
// non-fatal Partial "unreachable" (ADR-0018 §4), anything else Errored.
func (c *RDSCollector) completeness(service, region string, collected int, err error) collect.Completeness {
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

func (c *RDSCollector) completeCount(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Complete, Collected: collected}
}

// completeAttrs records an attribute pass: Complete, or Partial with the first gap
// reason when a per-snapshot attribute read failed.
func (c *RDSCollector) completeAttrs(sink collect.Sink, service, region string, checked int, reason string) {
	status := collect.Complete
	if reason != "" {
		status = collect.Partial
	}
	_ = sink.Complete(collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: status, Collected: checked, Reason: reason})
}

func (c *RDSCollector) budgetGap(service, region string) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Reason: "budget exhausted"}
}

func (c *RDSCollector) cancelledGap(service, region string, collected int) collect.Completeness {
	return collect.Completeness{Service: service, Region: region, Scope: c.scope(), Status: collect.Partial, Collected: collected, Reason: "cancelled"}
}

func (c *RDSCollector) markBudget(sink collect.Sink, region string, services ...string) {
	for _, s := range services {
		_ = sink.Complete(c.budgetGap(s, region))
	}
}

// callGap classifies a per-snapshot attribute read error into a gap reason (never
// empty).
func (c *RDSCollector) callGap(err error) string {
	switch {
	case isDenied(err):
		return "denied"
	case isThrottle(err):
		return "throttled"
	}
	return redact.String(err.Error())
}

func (c *RDSCollector) scope() collect.Scope { return collect.Scope{Account: c.account} }

// evidence builds a redacted, secret-free envelope for one RDS read. These Describe
// responses carry configuration only; they still pass through redaction as defence
// in depth.
func (c *RDSCollector) evidence(operation, region string, response any) collect.Envelope {
	raw, err := json.Marshal(response)
	if err != nil {
		raw = []byte(`null`)
	}
	return collect.Envelope{
		Provider: model.AWS, Service: "rds", Operation: operation, Region: region,
		Scope:      c.scope(),
		Response:   json.RawMessage(redact.String(string(raw))),
		Provenance: collect.Provenance{APIVersion: rdsAPIVersion, Collector: rdsCollectorID},
	}
}

// intAttr renders an optional int32 as its decimal string, or "" when unset.
func intAttr(n *int32) string {
	if n == nil {
		return ""
	}
	return strconv.Itoa(int(*n))
}

// appendErr appends a non-nil error.
func appendErr(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}
