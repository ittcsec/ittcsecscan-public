package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubEBS is an offline ebsSnapshotAPI: a per-region snapshot list, a per-snapshot
// public flag (which createVolumePermission the attribute read returns), and
// optional per-call errors keyed "op@region" or "attr@snapshotId".
type stubEBS struct {
	byRegion map[string][]ec2types.Snapshot
	public   map[string]bool  // snapshotId -> shared with "all"
	errs     map[string]error // "DescribeSnapshots@region" or "attr@snapshotId"
}

func (s *stubEBS) DescribeSnapshots(_ context.Context, _ *ec2.DescribeSnapshotsInput, o ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	r := ec2Region(o)
	if err := s.errs["DescribeSnapshots@"+r]; err != nil {
		return nil, err
	}
	return &ec2.DescribeSnapshotsOutput{Snapshots: s.byRegion[r]}, nil
}

func (s *stubEBS) DescribeSnapshotAttribute(_ context.Context, in *ec2.DescribeSnapshotAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error) {
	id := ""
	if in.SnapshotId != nil {
		id = *in.SnapshotId
	}
	if err := s.errs["attr@"+id]; err != nil {
		return nil, err
	}
	out := &ec2.DescribeSnapshotAttributeOutput{SnapshotId: in.SnapshotId}
	if s.public[id] {
		out.CreateVolumePermissions = []ec2types.CreateVolumePermission{{Group: ec2types.PermissionGroupAll}}
	}
	return out, nil
}

func runEBS(t *testing.T, api ebsSnapshotAPI, regions ...string) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newEBSSnapshotCollector(acctID, api, regions).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func snap(id string) ec2types.Snapshot {
	return ec2types.Snapshot{SnapshotId: ptr(id), VolumeId: ptr("vol-" + id), State: ec2types.SnapshotStateCompleted, OwnerId: ptr(acctID)}
}

func dataStoreNode(s collect.Scan, idSuffix string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeDataStore && strings.HasSuffix(n.NativeID, idSuffix) {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestEBSSnapshotPublicShare proves the attribute pass records public_shared from
// createVolumePermission: a snapshot shared with "all" is true, an unshared one is
// false, and the completeness is Complete for both the list and the attribute pass.
func TestEBSSnapshotPublicShare(t *testing.T) {
	s := runEBS(t, &stubEBS{
		byRegion: map[string][]ec2types.Snapshot{"us-east-1": {snap("pub"), snap("priv")}},
		public:   map[string]bool{"pub": true},
	}, "us-east-1")

	if c := completenessAt(s, "ec2.snapshots", "us-east-1"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("ec2.snapshots = %+v, want complete/2", c)
	}
	if c := completenessAt(s, "ec2.snapshotAttributes", "us-east-1"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("ec2.snapshotAttributes = %+v, want complete/2", c)
	}
	pub, ok := dataStoreNode(s, "snapshot/pub")
	if !ok || pub.Attributes["public_shared"] != "true" {
		t.Errorf("public snapshot public_shared = %q (ok=%v)", pub.Attributes["public_shared"], ok)
	}
	priv, ok := dataStoreNode(s, "snapshot/priv")
	if !ok || priv.Attributes["public_shared"] != "false" {
		t.Errorf("private snapshot public_shared = %q (ok=%v)", priv.Attributes["public_shared"], ok)
	}
}

// TestEBSSnapshotAttrFailureIsUnknown proves a snapshot whose attribute read failed
// is public_shared "unknown" (never a silent "false"), and the attribute pass is
// Partial with the failure reason while the list stays Complete.
func TestEBSSnapshotAttrFailureIsUnknown(t *testing.T) {
	s := runEBS(t, &stubEBS{
		byRegion: map[string][]ec2types.Snapshot{"us-east-1": {snap("x")}},
		errs:     map[string]error{"attr@x": apiErr("AccessDenied")},
	}, "us-east-1")

	n, ok := dataStoreNode(s, "snapshot/x")
	if !ok || n.Attributes["public_shared"] != "unknown" {
		t.Errorf("snapshot with failed attribute read public_shared = %q (ok=%v), want unknown", n.Attributes["public_shared"], ok)
	}
	if c := completenessAt(s, "ec2.snapshotAttributes", "us-east-1"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("ec2.snapshotAttributes = %+v, want partial/denied", c)
	}
	if c := completenessAt(s, "ec2.snapshots", "us-east-1"); c.Status != collect.Complete {
		t.Errorf("ec2.snapshots = %+v, want complete", c)
	}
}

// TestEBSSnapshotDeniedListIsGap proves a denied list is Denied with no nodes, and
// the attribute pass is an honest Complete/0 (nothing to check), never a false gap.
func TestEBSSnapshotDeniedListIsGap(t *testing.T) {
	s := runEBS(t, &stubEBS{errs: map[string]error{"DescribeSnapshots@us-east-1": apiErr("UnauthorizedOperation")}}, "us-east-1")
	if statusOf(s, "ec2.snapshots") != collect.Denied {
		t.Errorf("ec2.snapshots = %s, want denied", statusOf(s, "ec2.snapshots"))
	}
	if c := completenessAt(s, "ec2.snapshotAttributes", "us-east-1"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("ec2.snapshotAttributes = %+v, want complete/0", c)
	}
	if nodesByType(s)[model.NodeDataStore] != 0 {
		t.Error("no snapshot nodes should be emitted on a denied list")
	}
}

// TestEBSSnapshotRegionNotEnabled proves an opt-in region that is not enabled is
// Unsupported for the list, never a silent skip.
func TestEBSSnapshotRegionNotEnabled(t *testing.T) {
	s := runEBS(t, &stubEBS{errs: map[string]error{"DescribeSnapshots@ap-east-1": apiErr("OptInRequired")}}, "ap-east-1")
	if c := completenessAt(s, "ec2.snapshots", "ap-east-1"); c.Status != collect.Unsupported || c.Reason != "region not enabled" {
		t.Errorf("ec2.snapshots@ap-east-1 = %+v, want unsupported/region not enabled", c)
	}
}

// completenessAt returns the completeness for a (service, region) pair.
func completenessAt(s collect.Scan, service, region string) collect.Completeness {
	for _, c := range s.Completeness {
		if c.Service == service && c.Region == region {
			return c
		}
	}
	return collect.Completeness{}
}
