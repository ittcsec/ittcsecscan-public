package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubRDS is an offline rdsAPI: the same estate in every region, recording each
// call's region, with per-"op@region" error injection and per-snapshot restore
// attributes.
type stubRDS struct {
	instances     []rdstypes.DBInstance
	instancePages [][]rdstypes.DBInstance // if set, DescribeDBInstances paginates
	clusters      []rdstypes.DBCluster
	snapshots     []rdstypes.DBSnapshot
	clusterSnaps  []rdstypes.DBClusterSnapshot
	snapAttrs     map[string][]string // snapshot id -> restore attribute values
	clusterAttrs  map[string][]string // cluster snapshot id -> restore attribute values

	errs    map[string]error // "op@region" -> error
	calls   int
	regions []string
}

func rdsRegion(opts []func(*rds.Options)) string {
	var o rds.Options
	for _, f := range opts {
		f(&o)
	}
	return o.Region
}

func (s *stubRDS) hit(op string, o []func(*rds.Options)) error {
	s.calls++
	r := rdsRegion(o)
	s.regions = append(s.regions, r)
	return s.errs[op+"@"+r]
}

func (s *stubRDS) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, o ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if err := s.hit("DescribeDBInstances", o); err != nil {
		return nil, err
	}
	if len(s.instancePages) > 0 {
		page := 0
		if in.Marker != nil {
			page = int((*in.Marker)[0] - '0')
		}
		out := &rds.DescribeDBInstancesOutput{}
		if page < len(s.instancePages) {
			out.DBInstances = s.instancePages[page]
		}
		if page+1 < len(s.instancePages) {
			out.Marker = ptr(string(rune('0' + page + 1)))
		}
		return out, nil
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: s.instances}, nil
}

func (s *stubRDS) DescribeDBClusters(_ context.Context, _ *rds.DescribeDBClustersInput, o ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	if err := s.hit("DescribeDBClusters", o); err != nil {
		return nil, err
	}
	return &rds.DescribeDBClustersOutput{DBClusters: s.clusters}, nil
}

func (s *stubRDS) DescribeDBSnapshots(_ context.Context, _ *rds.DescribeDBSnapshotsInput, o ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error) {
	if err := s.hit("DescribeDBSnapshots", o); err != nil {
		return nil, err
	}
	return &rds.DescribeDBSnapshotsOutput{DBSnapshots: s.snapshots}, nil
}

func (s *stubRDS) DescribeDBSnapshotAttributes(_ context.Context, in *rds.DescribeDBSnapshotAttributesInput, o ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error) {
	if err := s.hit("DescribeDBSnapshotAttributes", o); err != nil {
		return nil, err
	}
	res := &rdstypes.DBSnapshotAttributesResult{DBSnapshotIdentifier: in.DBSnapshotIdentifier}
	if vals, ok := s.snapAttrs[deref(in.DBSnapshotIdentifier)]; ok {
		res.DBSnapshotAttributes = []rdstypes.DBSnapshotAttribute{{AttributeName: ptr("restore"), AttributeValues: vals}}
	}
	return &rds.DescribeDBSnapshotAttributesOutput{DBSnapshotAttributesResult: res}, nil
}

func (s *stubRDS) DescribeDBClusterSnapshots(_ context.Context, _ *rds.DescribeDBClusterSnapshotsInput, o ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotsOutput, error) {
	if err := s.hit("DescribeDBClusterSnapshots", o); err != nil {
		return nil, err
	}
	return &rds.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: s.clusterSnaps}, nil
}

func (s *stubRDS) DescribeDBClusterSnapshotAttributes(_ context.Context, in *rds.DescribeDBClusterSnapshotAttributesInput, o ...func(*rds.Options)) (*rds.DescribeDBClusterSnapshotAttributesOutput, error) {
	if err := s.hit("DescribeDBClusterSnapshotAttributes", o); err != nil {
		return nil, err
	}
	res := &rdstypes.DBClusterSnapshotAttributesResult{DBClusterSnapshotIdentifier: in.DBClusterSnapshotIdentifier}
	if vals, ok := s.clusterAttrs[deref(in.DBClusterSnapshotIdentifier)]; ok {
		res.DBClusterSnapshotAttributes = []rdstypes.DBClusterSnapshotAttribute{{AttributeName: ptr("restore"), AttributeValues: vals}}
	}
	return &rds.DescribeDBClusterSnapshotAttributesOutput{DBClusterSnapshotAttributesResult: res}, nil
}

func runRDS(t *testing.T, regions []string, api rdsAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newRDSCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func rdsNode(s collect.Scan, arn string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeDataStore && n.NativeID == arn {
			return n, true
		}
	}
	return collect.Node{}, false
}

var oneRegion = []string{"us-east-1"}

// TestRDSMapsInstances proves a DB instance becomes a data-store node keyed by ARN,
// with the security-relevant facts recorded and cross-references (KMS key, VPC
// security groups, VPC/subnet group) kept as id facts.
func TestRDSMapsInstances(t *testing.T) {
	arn := "arn:aws:rds:us-east-1:123456789012:db:prod-db"
	api := &stubRDS{instances: []rdstypes.DBInstance{{
		DBInstanceArn:                    ptr(arn),
		DBInstanceIdentifier:             ptr("prod-db"),
		Engine:                           ptr("postgres"),
		EngineVersion:                    ptr("16.3"),
		DBInstanceStatus:                 ptr("available"),
		DBInstanceClass:                  ptr("db.t3.medium"),
		PubliclyAccessible:               bptr(true),
		StorageEncrypted:                 bptr(true),
		KmsKeyId:                         ptr("arn:aws:kms:us-east-1:123456789012:key/abcd"),
		IAMDatabaseAuthenticationEnabled: bptr(false),
		DeletionProtection:               bptr(false),
		MultiAZ:                          bptr(true),
		BackupRetentionPeriod:            i32(7),
		AllocatedStorage:                 i32(100),
		StorageType:                      ptr("gp3"),
		AvailabilityZone:                 ptr("us-east-1a"),
		Endpoint:                         &rdstypes.Endpoint{Address: ptr("prod-db.abc.us-east-1.rds.amazonaws.com"), Port: i32(5432)},
		DBSubnetGroup:                    &rdstypes.DBSubnetGroup{DBSubnetGroupName: ptr("default-vpc"), VpcId: ptr("vpc-123")},
		VpcSecurityGroups:                []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: ptr("sg-2")}, {VpcSecurityGroupId: ptr("sg-1")}},
		TagList:                          []rdstypes.Tag{{Key: ptr("env"), Value: ptr("prod")}},
	}}}
	s := runRDS(t, oneRegion, api)

	n, ok := rdsNode(s, arn)
	if !ok {
		t.Fatal("prod-db not emitted as a data-store node")
	}
	for k, v := range map[string]string{
		"rds_type": "db_instance", "engine": "postgres", "status": "available",
		"publicly_accessible": "true", "storage_encrypted": "true",
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd",
		"multi_az":   "true", "backup_retention_days": "7",
		"endpoint_address": "prod-db.abc.us-east-1.rds.amazonaws.com", "endpoint_port": "5432",
		"db_subnet_group": "default-vpc", "vpc_id": "vpc-123",
		"vpc_security_group_ids": "sg-1,sg-2", "tag:env": "prod", "region": "us-east-1",
	} {
		if n.Attributes[k] != v {
			t.Errorf("prod-db %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	if c := completenessOf(s, svcDBInstances); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("%s = %+v, want complete/1", svcDBInstances, c)
	}
}

// TestRDSMapsClusters proves a DB cluster becomes a data-store node with its facts.
func TestRDSMapsClusters(t *testing.T) {
	arn := "arn:aws:rds:us-east-1:123456789012:cluster:aurora-1"
	api := &stubRDS{clusters: []rdstypes.DBCluster{{
		DBClusterArn:        ptr(arn),
		DBClusterIdentifier: ptr("aurora-1"),
		Engine:              ptr("aurora-postgresql"),
		EngineMode:          ptr("provisioned"),
		Status:              ptr("available"),
		PubliclyAccessible:  bptr(false),
		StorageEncrypted:    bptr(true),
		KmsKeyId:            ptr("key/xyz"),
		Endpoint:            ptr("aurora-1.cluster.us-east-1.rds.amazonaws.com"),
		ReaderEndpoint:      ptr("aurora-1.cluster-ro.us-east-1.rds.amazonaws.com"),
		Port:                i32(5432),
		DBSubnetGroup:       ptr("default-vpc"),
		VpcSecurityGroups:   []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: ptr("sg-9")}},
	}}}
	s := runRDS(t, oneRegion, api)
	n, ok := rdsNode(s, arn)
	if !ok {
		t.Fatal("aurora-1 cluster not emitted")
	}
	for k, v := range map[string]string{
		"rds_type": "db_cluster", "engine": "aurora-postgresql", "engine_mode": "provisioned",
		"storage_encrypted": "true", "reader_endpoint_address": "aurora-1.cluster-ro.us-east-1.rds.amazonaws.com",
		"vpc_security_group_ids": "sg-9",
	} {
		if n.Attributes[k] != v {
			t.Errorf("aurora-1 %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
}

// TestRDSPublicSnapshotDetected proves the restore=all fact makes a manual snapshot
// public, a manual snapshot shared only with named accounts is not public, and an
// automated snapshot is recorded not-public with no attribute call.
func TestRDSPublicSnapshotDetected(t *testing.T) {
	pubArn := "arn:aws:rds:us-east-1:123456789012:snapshot:pub"
	privArn := "arn:aws:rds:us-east-1:123456789012:snapshot:priv"
	autoArn := "arn:aws:rds:us-east-1:123456789012:snapshot:auto"
	api := &stubRDS{
		snapshots: []rdstypes.DBSnapshot{
			{DBSnapshotArn: ptr(pubArn), DBSnapshotIdentifier: ptr("pub"), SnapshotType: ptr("manual"), Engine: ptr("mysql")},
			{DBSnapshotArn: ptr(privArn), DBSnapshotIdentifier: ptr("priv"), SnapshotType: ptr("manual"), Engine: ptr("mysql")},
			{DBSnapshotArn: ptr(autoArn), DBSnapshotIdentifier: ptr("auto"), SnapshotType: ptr("automated"), Engine: ptr("mysql")},
		},
		snapAttrs: map[string][]string{
			"pub":  {"123456789012", "all"},
			"priv": {"999988887777"},
		},
	}
	s := runRDS(t, oneRegion, api)

	if n, _ := rdsNode(s, pubArn); n.Attributes["public_shared"] != "true" {
		t.Errorf("pub public_shared = %q, want true", n.Attributes["public_shared"])
	}
	if n, _ := rdsNode(s, privArn); n.Attributes["public_shared"] != "false" {
		t.Errorf("priv public_shared = %q, want false", n.Attributes["public_shared"])
	}
	if n, _ := rdsNode(s, autoArn); n.Attributes["public_shared"] != "false" {
		t.Errorf("auto public_shared = %q, want false", n.Attributes["public_shared"])
	}
	// Only the two manual snapshots trigger an attribute call.
	if c := completenessOf(s, svcSnapshotAttrs); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("%s = %+v, want complete/2", svcSnapshotAttrs, c)
	}
	if c := completenessOf(s, svcDBSnapshots); c.Status != collect.Complete || c.Collected != 3 {
		t.Errorf("%s = %+v, want complete/3", svcDBSnapshots, c)
	}
}

// TestRDSSnapshotAttrDeniedIsPartial proves a denied per-snapshot attribute read
// makes the attribute pass Partial "denied" and the snapshot public_shared
// "unknown", never silently "false"; the snapshot node is still emitted.
func TestRDSSnapshotAttrDeniedIsPartial(t *testing.T) {
	arn := "arn:aws:rds:us-east-1:123456789012:snapshot:m1"
	api := &stubRDS{
		snapshots: []rdstypes.DBSnapshot{{DBSnapshotArn: ptr(arn), DBSnapshotIdentifier: ptr("m1"), SnapshotType: ptr("manual")}},
		errs:      map[string]error{"DescribeDBSnapshotAttributes@us-east-1": apiErr("AccessDenied")},
	}
	s := runRDS(t, oneRegion, api)
	n, ok := rdsNode(s, arn)
	if !ok {
		t.Fatal("m1 snapshot must still be emitted when its attribute read is denied")
	}
	if n.Attributes["public_shared"] != "unknown" {
		t.Errorf("m1 public_shared = %q, want unknown", n.Attributes["public_shared"])
	}
	if c := completenessOf(s, svcSnapshotAttrs); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("%s = %+v, want partial denied", svcSnapshotAttrs, c)
	}
}

// TestRDSClusterSnapshotPublic proves the same public-share detection for cluster
// snapshots.
func TestRDSClusterSnapshotPublic(t *testing.T) {
	arn := "arn:aws:rds:us-east-1:123456789012:cluster-snapshot:cs"
	api := &stubRDS{
		clusterSnaps: []rdstypes.DBClusterSnapshot{{DBClusterSnapshotArn: ptr(arn), DBClusterSnapshotIdentifier: ptr("cs"), SnapshotType: ptr("manual"), DBClusterIdentifier: ptr("aurora-1")}},
		clusterAttrs: map[string][]string{"cs": {"all"}},
	}
	s := runRDS(t, oneRegion, api)
	n, ok := rdsNode(s, arn)
	if !ok {
		t.Fatal("cluster snapshot not emitted")
	}
	if n.Attributes["public_shared"] != "true" || n.Attributes["rds_type"] != "db_cluster_snapshot" || n.Attributes["source_db_cluster"] != "aurora-1" {
		t.Errorf("cs attrs = %v", n.Attributes)
	}
	if c := completenessOf(s, svcClusterSnapAttrs); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("%s = %+v, want complete/1", svcClusterSnapAttrs, c)
	}
}

// TestRDSListDeniedIsGap proves a denied list is a Denied gap that does not fail the
// run or block the other enumerations.
func TestRDSListDeniedIsGap(t *testing.T) {
	api := &stubRDS{
		clusters: []rdstypes.DBCluster{{DBClusterArn: ptr("arn:aws:rds:us-east-1:123456789012:cluster:c"), DBClusterIdentifier: ptr("c")}},
		errs:     map[string]error{"DescribeDBInstances@us-east-1": apiErr("AccessDenied")},
	}
	s := runRDS(t, oneRegion, api)
	if statusOf(s, svcDBInstances) != collect.Denied {
		t.Errorf("%s = %s, want denied", svcDBInstances, statusOf(s, svcDBInstances))
	}
	if statusOf(s, svcDBClusters) != collect.Complete {
		t.Error("clusters should still collect when instances is denied")
	}
}

// TestRDSRegionNotEnabledUnsupported proves an opt-in region the account has not
// enabled is Unsupported "region not enabled".
func TestRDSRegionNotEnabledUnsupported(t *testing.T) {
	api := &stubRDS{errs: map[string]error{"DescribeDBInstances@us-east-1": apiErr("OptInRequired")}}
	s := runRDS(t, oneRegion, api)
	c := completenessOf(s, svcDBInstances)
	if c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcDBInstances, c)
	}
}

// TestRDSInvalidClientTokenIsRegionNotEnabled proves an opt-in region the account
// has not enabled, which RDS rejects with InvalidClientTokenId, is a represented
// Unsupported "region not enabled" gap and not a fatal error.
func TestRDSInvalidClientTokenIsRegionNotEnabled(t *testing.T) {
	api := &stubRDS{errs: map[string]error{"DescribeDBInstances@us-east-1": apiErr("InvalidClientTokenId")}}
	var s collect.Scan
	if err := newRDSCollector(acctID, api, oneRegion).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a not-enabled region must not fail the run: %v", err)
	}
	c := completenessOf(s, svcDBInstances)
	if c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("%s = %+v, want unsupported region-not-enabled", svcDBInstances, c)
	}
}

// TestRDSTransportIsPartialUnreachable proves a transport failure (no API error
// code) is a non-fatal Partial "unreachable", not a fatal error.
func TestRDSTransportIsPartialUnreachable(t *testing.T) {
	api := &stubRDS{errs: map[string]error{"DescribeDBInstances@us-east-1": errors.New("dial tcp: i/o timeout")}}
	var s collect.Scan
	if err := newRDSCollector(acctID, api, oneRegion).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a transport failure must not fail the run: %v", err)
	}
	c := completenessOf(s, svcDBInstances)
	if c.Status != collect.Partial || c.Reason != "unreachable" {
		t.Errorf("%s = %+v, want partial unreachable", svcDBInstances, c)
	}
}

// TestRDSFanOutAllRegions proves every declared region is visited and records one
// completeness per (service, region).
func TestRDSFanOutAllRegions(t *testing.T) {
	regions := []string{"us-east-1", "eu-west-1"}
	api := &stubRDS{}
	s := runRDS(t, regions, api)
	seen := map[string]int{}
	for _, r := range api.regions {
		seen[r]++
	}
	if seen["us-east-1"] == 0 || seen["eu-west-1"] == 0 {
		t.Errorf("not every region visited: %v", seen)
	}
	// 6 completeness services x 2 regions.
	if len(s.Completeness) != 12 {
		t.Errorf("completeness records = %d, want 12", len(s.Completeness))
	}
}

// TestRDSBudgetExhaustion proves the shared budget bounds the sweep and marks the
// services not reached Partial "budget exhausted".
func TestRDSBudgetExhaustion(t *testing.T) {
	api := &stubRDS{}
	c := newRDSCollector(acctID, api, oneRegion)
	c.budget = collect.NewBudget(2) // instances + clusters lists only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if api.calls != 2 {
		t.Errorf("made %d calls under a 2-call budget; want 2", api.calls)
	}
	for _, svc := range []string{svcDBSnapshots, svcSnapshotAttrs, svcDBClusterSnapshots, svcClusterSnapAttrs} {
		if got := completenessOf(s, svc); got.Status != collect.Partial || got.Reason != "budget exhausted" {
			t.Errorf("%s = %+v, want partial budget-exhausted", svc, got)
		}
	}
}

// TestRDSInstancesPaginate proves the Marker is followed across instance pages.
func TestRDSInstancesPaginate(t *testing.T) {
	api := &stubRDS{instancePages: [][]rdstypes.DBInstance{
		{{DBInstanceArn: ptr("arn:aws:rds:us-east-1:123456789012:db:a"), DBInstanceIdentifier: ptr("a")}},
		{{DBInstanceArn: ptr("arn:aws:rds:us-east-1:123456789012:db:b"), DBInstanceIdentifier: ptr("b")}},
	}}
	s := runRDS(t, oneRegion, api)
	if c := completenessOf(s, svcDBInstances); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("%s = %+v, want complete/2 across pages", svcDBInstances, c)
	}
	if n := nodesByType(s)[model.NodeDataStore]; n != 2 {
		t.Errorf("instances across pages = %d, want 2", n)
	}
}

// TestRDSEvidenceRedactsToken proves the evidence body is scrubbed.
func TestRDSEvidenceRedactsToken(t *testing.T) {
	token := "AKIA" + strings.Repeat("Z", 16)
	api := &stubRDS{instances: []rdstypes.DBInstance{{
		DBInstanceArn: ptr("arn:aws:rds:us-east-1:123456789012:db:x"), DBInstanceIdentifier: ptr(token),
	}}}
	s := runRDS(t, oneRegion, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
