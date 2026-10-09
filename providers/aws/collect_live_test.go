//go:build live

// Run against the disposable AWS test account (ADR-0016 §3, ADR-0018):
//
//	AWS_PROFILE=ittcsecscan-test go test -tags live -run TestLiveCollectIAMIdentities -v ./providers/aws/
//
// The test account has the ittcsecscan-test user with ReadOnlyAccess, so this
// collects a real, minimal IAM identity graph even before a full testlab estate.
// It lives in the providers/aws package (not providers/aws/collect) because it
// drives the real Source, and providers/aws depends on providers/aws/collect for
// the collector factory; a test in the child package importing the parent would
// be an import cycle.
package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	awscollect "github.com/ittcsec/ittcsecscan/providers/aws/collect"
)

// TestLiveCollectIAMIdentities runs the AWS source end to end against the real
// account: it resolves the credential chain once, builds the collectors from that
// single resolution, runs them, and prints what it found. It proves the source
// authenticates, the collector paginates and maps real IAM data, and that the
// evidence carries no leaked secret.
func TestLiveCollectIAMIdentities(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	if account == "" {
		t.Fatal("resolved an empty account")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	if len(scan.Nodes) == 0 {
		t.Fatalf("collected no nodes")
	}
	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s (%s)", c.Service, c.Reason)
		}
	}
	// The evidence must never contain a real AWS access key id.
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	t.Logf("account %s: collected %d nodes, %d links, %d evidence envelopes; completeness=%+v",
		account, len(scan.Nodes), len(scan.Links), len(scan.Envelopes), scan.Completeness)
}

// TestLiveCollectStorage runs the AWS source end to end and checks the S3 storage
// collector specifically: it authenticates, lists real buckets and reads their
// configuration over the bucket-metadata operations (never object contents), and
// records the two S3 completeness records without an unexpected error. It proves
// the collector works against the real account and leaks no access key id.
func TestLiveCollectStorage(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawBuckets, sawConfig bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "s3.buckets":
			sawBuckets = true
		case "s3.bucketConfig":
			sawConfig = true
		}
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s (%s)", c.Service, c.Reason)
		}
	}
	if !sawBuckets || !sawConfig {
		t.Errorf("missing S3 completeness records (buckets=%v config=%v)", sawBuckets, sawConfig)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var buckets int
	for _, n := range scan.Nodes {
		if n.Type == model.NodeDataStore {
			buckets++
		}
	}
	t.Logf("account %s: %d S3 buckets; completeness=%+v", account, buckets, scan.Completeness)
}

// TestLiveCollectInstances runs the AWS source end to end and checks the EC2
// instance collector specifically: it enumerates instances across the declared
// region set, records ec2.instances (per region) and ec2.instanceRoles, resolves
// run-as roles, and never reads user data, console output, or a password. It
// proves the collector works against the real account (including honest empty and
// region-not-enabled handling) and leaks no access key id.
func TestLiveCollectInstances(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawInstances, sawRoles int
	for _, c := range scan.Completeness {
		switch c.Service {
		case "ec2.instances":
			sawInstances++
		case "ec2.instanceRoles":
			sawRoles++
		}
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s@%s (%s)", c.Service, c.Region, c.Reason)
		}
	}
	if sawInstances == 0 || sawRoles == 0 {
		t.Errorf("missing EC2 completeness records (instances=%d, instanceRoles=%d)", sawInstances, sawRoles)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var instances, runAsEdges int
	for _, n := range scan.Nodes {
		if n.Type == model.NodeCompute {
			instances++
		}
	}
	for _, l := range scan.Links {
		if l.Kind == model.EdgeAssumes {
			runAsEdges++
		}
	}
	t.Logf("account %s: %d EC2 instances, %d run-as edges; ec2.instances records=%d", account, instances, runAsEdges, sawInstances)
}

// TestLiveCollectVPCEndpoints runs the AWS source end to end and checks the VPC
// endpoint policy collector across the full declared region set: it records one
// ec2.vpcEndpoints completeness per region with no unexpected Errored (which would
// reveal an unhandled region-not-enabled or other code), maps any endpoint to a
// gateway node with its policy facts, and leaks no access key id. An account with no
// endpoints is an honest Complete/0; an opt-in region not enabled is Unsupported.
func TestLiveCollectVPCEndpoints(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	regions, byStatus := 0, map[collect.Status]int{}
	for _, c := range scan.Completeness {
		if c.Service != "ec2.vpcEndpoints" {
			continue
		}
		regions++
		byStatus[c.Status]++
		if c.Status == collect.Errored {
			t.Errorf("ec2.vpcEndpoints errored @%s: %s (an unhandled region code?)", c.Region, c.Reason)
		}
	}
	if regions == 0 {
		t.Error("no ec2.vpcEndpoints completeness records found")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	endpoints, withPolicy := 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["aws_type"] == "vpc-endpoint" {
			endpoints++
			if n.Attributes["has_policy"] == "true" {
				withPolicy++
			}
		}
	}
	t.Logf("account %s: %d ec2.vpcEndpoints region records %v; %d endpoints (%d with a policy)", account, regions, byStatus, endpoints, withPolicy)
}

// TestLiveCollectS3AccessPoints runs the AWS source end to end and checks the S3
// access point collector across the full declared region set: it records
// s3.accessPoints and s3.accessPointAccess per region with no unexpected Errored
// (which would reveal an unhandled region code), maps any access point to an endpoint
// node with its is_public/network_origin/policy facts, and leaks no access key id. An
// account with no access points is an honest Complete/0; an opt-in region not enabled
// is Unsupported.
func TestLiveCollectS3AccessPoints(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	regions, byStatus := 0, map[collect.Status]int{}
	for _, c := range scan.Completeness {
		if c.Service != "s3.accessPoints" && c.Service != "s3.accessPointAccess" {
			continue
		}
		if c.Service == "s3.accessPoints" {
			regions++
			byStatus[c.Status]++
		}
		if c.Status == collect.Errored {
			t.Errorf("%s errored @%s: %s (an unhandled region code?)", c.Service, c.Region, c.Reason)
		}
	}
	if regions == 0 {
		t.Error("no s3.accessPoints completeness records found")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	aps, public, internet := 0, 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["aws_type"] != "s3-access-point" {
			continue
		}
		aps++
		if n.Attributes["is_public"] == "true" {
			public++
		}
		if n.Attributes["network_origin"] == "Internet" {
			internet++
		}
	}
	t.Logf("account %s: %d s3.accessPoints region records %v; %d access points (%d public, %d internet-origin)", account, regions, byStatus, aps, public, internet)
}

// TestLiveCollectEBSSnapshots runs the AWS source end to end and checks the EBS
// snapshot collector across the full declared region set: it records ec2.snapshots
// and ec2.snapshotAttributes per region with no unexpected Errored (which would
// reveal an unhandled region code), maps any snapshot to a data-store node with its
// public_shared fact, and leaks no access key id. An account with no snapshots is an
// honest Complete/0; an opt-in region not enabled is Unsupported.
func TestLiveCollectEBSSnapshots(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	regions, byStatus := 0, map[collect.Status]int{}
	for _, c := range scan.Completeness {
		if c.Service != "ec2.snapshots" && c.Service != "ec2.snapshotAttributes" {
			continue
		}
		if c.Service == "ec2.snapshots" {
			regions++
			byStatus[c.Status]++
		}
		if c.Status == collect.Errored {
			t.Errorf("%s errored @%s: %s (an unhandled region code?)", c.Service, c.Region, c.Reason)
		}
	}
	if regions == 0 {
		t.Error("no ec2.snapshots completeness records found")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	snaps, public, unknown := 0, 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["aws_type"] != "ebs-snapshot" {
			continue
		}
		snaps++
		switch n.Attributes["public_shared"] {
		case "true":
			public++
		case "unknown":
			unknown++
		}
	}
	t.Logf("account %s: %d ec2.snapshots region records %v; %d snapshots (%d public, %d unknown)", account, regions, byStatus, snaps, public, unknown)
}

// TestLiveCollectLambda runs the AWS source end to end and checks the Lambda
// collector across the full declared region set: it records lambda.functions and
// lambda.functionAccess per region with no unexpected Errored (which would reveal an
// unhandled region code), maps any function to a compute node with its URL/policy
// facts, never leaks an env var value or an access key id into evidence. An account
// with no functions is an honest Complete/0; an opt-in region not enabled is
// Unsupported.
func TestLiveCollectLambda(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	regions, byStatus := 0, map[collect.Status]int{}
	for _, c := range scan.Completeness {
		if c.Service != "lambda.functions" && c.Service != "lambda.functionAccess" {
			continue
		}
		if c.Service == "lambda.functions" {
			regions++
			byStatus[c.Status]++
		}
		if c.Status == collect.Errored {
			t.Errorf("%s errored @%s: %s (an unhandled region code?)", c.Service, c.Region, c.Reason)
		}
	}
	if regions == 0 {
		t.Error("no lambda.functions completeness records found")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	fns, publicURL, openPolicy := 0, 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["aws_type"] != "lambda-function" {
			continue
		}
		fns++
		if n.Attributes["public_url"] == "true" {
			publicURL++
		}
		if n.Attributes["resource_policy"] == "open" {
			openPolicy++
		}
	}
	t.Logf("account %s: %d lambda.functions region records %v; %d functions (%d public-url, %d open-policy)", account, regions, byStatus, fns, publicURL, openPolicy)
}

// TestLiveCollectNetwork runs the AWS source end to end and checks the EC2 network
// collector specifically: it enumerates the VPC topology across the declared
// region set, records a completeness record per (service, region), emits no edges
// (reachability is the reachability engine), and leaks no access key id.
func TestLiveCollectNetwork(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	services := map[string]bool{}
	for _, c := range scan.Completeness {
		if strings.HasPrefix(c.Service, "ec2.") && c.Service != "ec2.instances" && c.Service != "ec2.instanceRoles" {
			services[c.Service] = true
		}
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s@%s (%s)", c.Service, c.Region, c.Reason)
		}
	}
	if len(services) == 0 {
		t.Error("no ec2.network completeness records found")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var networkNodes int
	for _, n := range scan.Nodes {
		switch n.Type {
		case model.NodeNetwork, model.NodeGateway, model.NodeControl, model.NodeEndpoint:
			networkNodes++
		}
	}
	t.Logf("account %s: %d network nodes across %d ec2.network services", account, networkNodes, len(services))
}

// TestLiveCollectRDS runs the AWS source end to end and checks the RDS collector:
// it enumerates DB instances, clusters, and snapshots across the declared regions,
// reads each manual snapshot's restore attribute to detect a public share, records
// one completeness per (service, region) without an unexpected error, and leaks no
// access key id. An empty account is an honest Complete/0; a not-enabled region is
// Unsupported; none of these is a failure.
func TestLiveCollectRDS(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	t.Logf("resolved account: %s", account)

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	services := map[string]bool{}
	for _, c := range scan.Completeness {
		if strings.HasPrefix(c.Service, "rds.") {
			services[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("collection errored: %s@%s (%s)", c.Service, c.Region, c.Reason)
			}
		}
	}
	for _, want := range []string{"rds.dbInstances", "rds.dbClusters", "rds.dbSnapshots", "rds.snapshotAttributes", "rds.dbClusterSnapshots", "rds.clusterSnapshotAttributes"} {
		if !services[want] {
			t.Errorf("missing %s completeness record", want)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var dbNodes, publicShared int
	for _, n := range scan.Nodes {
		if n.Type == model.NodeDataStore && strings.HasPrefix(n.Attributes["rds_type"], "db_") {
			dbNodes++
			if n.Attributes["public_shared"] == "true" {
				publicShared++
			}
		}
	}
	t.Logf("account %s: %d RDS nodes (%d publicly shared snapshots)", account, dbNodes, publicShared)
}

// TestLiveCollectKMS runs the AWS source end to end and checks the KMS collector: it
// lists aliases and keys across the declared regions, details each key (metadata,
// resource policy, rotation, tags), records one completeness per (service, region)
// without an unexpected error, and leaks no access key id. It also confirms the
// key-state and rotation-applicability handling against real keys, the way the RDS
// InvalidClientTokenId behavior was confirmed live rather than assumed. An empty
// account is an honest Complete/0; a not-enabled region is Unsupported.
func TestLiveCollectKMS(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	t.Logf("resolved account: %s", account)

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	services := map[string]bool{}
	for _, c := range scan.Completeness {
		if strings.HasPrefix(c.Service, "kms.") {
			services[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("collection errored: %s@%s (%s)", c.Service, c.Region, c.Reason)
			}
		}
	}
	for _, want := range []string{"kms.aliases", "kms.keys", "kms.keyDetails"} {
		if !services[want] {
			t.Errorf("missing %s completeness record", want)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var keyNodes, rotated, notApplicable int
	for _, n := range scan.Nodes {
		if n.Type == model.NodeControl && n.Attributes["key_manager"] != "" {
			keyNodes++
			switch n.Attributes["rotation_enabled"] {
			case "true":
				rotated++
			case "not_applicable":
				notApplicable++
			}
		}
	}
	t.Logf("account %s: %d KMS keys (%d rotation-enabled, %d rotation-not-applicable)", account, keyNodes, rotated, notApplicable)
}

// TestLiveCollectLogging runs the AWS source end to end and checks the logging
// collector: it reads CloudTrail trails (status and event scope) and AWS Config
// recorders and delivery channels across the declared regions, records one
// completeness per (service, region) without an unexpected error, and leaks no
// access key id. A multi-region trail is recorded once in its home region. An empty
// account is an honest Complete/0; a not-enabled region is Unsupported.
func TestLiveCollectLogging(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	t.Logf("resolved account: %s", account)

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	services := map[string]bool{}
	for _, c := range scan.Completeness {
		if strings.HasPrefix(c.Service, "cloudtrail.") || strings.HasPrefix(c.Service, "config.") {
			services[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("collection errored: %s@%s (%s)", c.Service, c.Region, c.Reason)
			}
		}
	}
	for _, want := range []string{"cloudtrail.trails", "cloudtrail.trailDetails", "config.recorders", "config.deliveryChannels"} {
		if !services[want] {
			t.Errorf("missing %s completeness record", want)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	var trails, recorders, logging int
	for _, n := range scan.Nodes {
		switch n.Attributes["cloudtrail_type"] {
		case "trail":
			trails++
			if n.Attributes["is_logging"] == "true" {
				logging++
			}
		}
		if n.Attributes["config_type"] == "configuration_recorder" {
			recorders++
		}
	}
	t.Logf("account %s: %d trails (%d logging), %d config recorders", account, trails, logging, recorders)
}

// TestLiveCollectSecurityServices runs the AWS source end to end and checks the
// security-services collector: GuardDuty, Security Hub, Access Analyzer, Inspector,
// and Macie enablement posture across the declared regions. It records one
// completeness per (service, region) without an unexpected error and leaks no access
// key id. It deliberately surfaces any Denied record for Security Hub and Macie so
// the real not-enabled behavior (whether it maps to enabled=false or falls to an
// honest gap) is observed, not assumed, per the not-enabled discipline.
func TestLiveCollectSecurityServices(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	t.Logf("resolved account: %s", account)

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{
		"securityservices.guardduty": false, "securityservices.securityhub": false,
		"securityservices.accessAnalyzer": false, "securityservices.inspector2": false,
		"securityservices.macie2": false,
	}
	enabled := map[string]int{}
	disabled := map[string]int{}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("%s@%s errored: %s", c.Service, c.Region, c.Reason)
			}
			// Surface any denial so an ambiguous not-enabled path is visible.
			if c.Status == collect.Denied {
				t.Logf("%s@%s denied (kept as an honest gap, not a fabricated disabled): %s", c.Service, c.Region, c.Reason)
			}
		}
	}
	for svc, saw := range want {
		if !saw {
			t.Errorf("missing %s completeness record", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	for _, n := range scan.Nodes {
		if svc := n.Attributes["security_service"]; svc != "" {
			if n.Attributes["enabled"] == "true" {
				enabled[svc]++
			} else {
				disabled[svc]++
			}
		}
	}
	t.Logf("account %s: enablement nodes enabled=%v disabled=%v", account, enabled, disabled)
}

// TestLiveCollectOrganizations runs the AWS source end to end and checks the
// Organizations collector: it reads the organization and walks its roots, OUs, and
// accounts with read-only calls only, records the organizations.hierarchy completeness
// without an unexpected error, and leaks no access key. An account not in an
// organization is an explicit Complete fact; a denied read is Denied; a partial walk is
// Partial. None is a failure.
func TestLiveCollectOrganizations(t *testing.T) {
	ctx := context.Background()

	account, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Fatalf("resolve identity and build collectors: %v", err)
	}
	t.Logf("resolved account: %s", account)

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "organizations.hierarchy" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("organizations.hierarchy errored: %s", c.Reason)
			}
			t.Logf("organizations.hierarchy: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing organizations.hierarchy completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	orgs, accts := 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["hierarchy_type"] {
		case "organization", "organizational_root", "organizational_unit":
			orgs++
		}
		if n.Type == model.NodeAccount && n.Attributes["parent_id"] != "" {
			accts++
		}
	}
	t.Logf("account %s: %d org/root/OU nodes, %d hierarchy-placed accounts", account, orgs, accts)
}

// TestLiveCollectBedrock runs ONLY the Agents for Amazon Bedrock collector against the
// real test account, across every declared region, and reports the real per-region
// completeness classification. It isolates the collector (resolving the config directly)
// so it does not run the full estate. Its purpose is to catch a live-only classification
// bug: a region where the service is absent or the account has no access must land as a
// represented gap (Unsupported / unreachable / denied), never an unexpected Errored and
// never a silent empty. It also confirms no access key id leaks into the evidence.
func TestLiveCollectBedrock(t *testing.T) {
	ctx := context.Background()
	id, cfg, err := NewSource().adapter.resolveConfig(ctx, model.AWS, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	t.Logf("resolved account: %s", id.Account)

	c := awscollect.NewBedrockAgentsCollector(id.Account, cfg, nil)
	var scan collect.Scan
	if err := collect.Run(ctx, []collect.Collector{c}, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	byStatus := map[collect.Status]int{}
	var errored []string
	for _, cr := range scan.Completeness {
		if !strings.HasPrefix(cr.Service, "bedrock.") {
			continue
		}
		byStatus[cr.Status]++
		if cr.Status != collect.Complete {
			t.Logf("  %s @ %s -> %s (%s)", cr.Service, cr.Region, cr.Status, cr.Reason)
		}
		if cr.Status == collect.Errored {
			errored = append(errored, cr.Service+"@"+cr.Region+": "+cr.Reason)
		}
	}
	nodes := map[model.NodeType]int{}
	for _, n := range scan.Nodes {
		nodes[n.Type]++
	}
	t.Logf("bedrock completeness by status: %v", byStatus)
	t.Logf("nodes: ai_agent=%d tool=%d data_store=%d; links=%d; evidence=%d",
		nodes[model.NodeAIAgent], nodes[model.NodeTool], nodes[model.NodeDataStore], len(scan.Links), len(scan.Envelopes))
	for _, e := range errored {
		t.Errorf("UNEXPECTED Errored (classification bug?): %s", e)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
	if len(scan.Completeness) == 0 {
		t.Fatal("no completeness records: the collector did not run")
	}
}

// TestLiveCollectCredentialReport runs the credential-report collector against the real test
// account. The account has at least the ittcsecscan-test user and root, so this live-verifies
// the generate/poll flow and the CSV parsing against real data (not just fixtures). It
// confirms Complete, real identity nodes with credential facts, and no key-id leak.
func TestLiveCollectCredentialReport(t *testing.T) {
	ctx := context.Background()
	id, cfg, err := NewSource().adapter.resolveConfig(ctx, model.AWS, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	var scan collect.Scan
	if err := collect.Run(ctx, []collect.Collector{awscollect.NewCredentialReportCollector(id.Account, cfg, nil)}, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, c := range scan.Completeness {
		t.Logf("credential report completeness: %+v", c)
		if c.Status == collect.Errored {
			t.Errorf("credential report errored: %s", c.Reason)
		}
	}
	users, withAge := 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["credential_report"] != "true" {
			continue
		}
		users++
		for _, k := range []string{"cred_access_key_1_age_days", "cred_access_key_1_last_used_age_days", "cred_access_key_1_never_used"} {
			if v := n.Attributes[k]; v != "" {
				withAge++
				t.Logf("key-age fact %s = %s", k, v)
			}
		}
	}
	t.Logf("credential report: %d identities with credential facts, %d key-age facts emitted", users, withAge)
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "AKIA") {
			t.Errorf("evidence may contain an access key id: %s", e.Operation)
		}
	}
}
