//go:build live

// Run against a disposable GCP test project (ADR-0016 §3, ADR-0018) whose
// credential is granted the read-only iam.serviceAccounts.list permission (for
// example a service account with roles/iam.securityReviewer or a custom role):
//
//	GOOGLE_APPLICATION_CREDENTIALS=... go test -tags live -run TestLiveCollectServiceAccounts -v ./providers/gcp/
//
// It drives the real Source, so it also exercises the single-credential
// resolution with both scopes. It lives in providers/gcp (not
// providers/gcp/collect) for the same reason the AWS and Azure live tests do:
// providers/gcp depends on providers/gcp/collect for the collector factory.
package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveCollectServiceAccounts resolves the GCP identity once with both scopes,
// builds the service-account collector from that credential, runs it, and prints
// what it found. It proves the source authenticates, the collector paginates and
// maps real service accounts over plain-HTTP REST, and that the evidence carries
// no leaked token.
func TestLiveCollectServiceAccounts(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project; set one to collect service accounts")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s (%s)", c.Service, c.Reason)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") { // an access-token prefix
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	t.Logf("project %s: collected %d nodes, %d evidence envelopes; completeness=%+v",
		project, len(scan.Nodes), len(scan.Envelopes), scan.Completeness)
}

// TestLiveCollectServiceAccountKeys runs the GCP source end to end and checks the
// service-account key-age collector: it lists the project's service accounts and each
// account's user-managed keys, mapping each key to a credential node with its age,
// records iam.serviceAccountKeys without an unexpected error, and leaks no access
// token. It surfaces the real outcome: Complete with N keys if the project has
// user-managed keys, Complete/0 if it has none (an honest empty), or Denied if the
// caller lacks iam.serviceAccountKeys.list, none a failure.
func TestLiveCollectServiceAccountKeys(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "iam.serviceAccountKeys" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("iam.serviceAccountKeys errored: %s", c.Reason)
			}
			t.Logf("iam.serviceAccountKeys: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing iam.serviceAccountKeys completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") { // an access-token prefix
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
		if strings.Contains(string(e.Response), "PRIVATE KEY") {
			t.Errorf("evidence may contain private key material: %s", e.Operation)
		}
	}
	keys := 0
	for _, n := range scan.Nodes {
		if n.Attributes["key_type"] == "user_managed" {
			keys++
		}
	}
	t.Logf("project %s: %d user-managed service-account key nodes", project, keys)
}

// TestLiveCollectWorkloadIdentityFederation runs the GCP source end to end and checks
// the workload identity federation collector: it lists the project's WIF pools and
// their providers, records iam.workloadIdentityPools and
// iam.workloadIdentityPoolProviders without an unexpected Errored, maps any provider
// to a gateway node with its external-trust facts, and leaks no access token. A
// project with no pools is an honest Complete/0; a caller without the permission is
// Denied; the IAM API disabled is Unsupported. WIF is global, so there is no region
// fan-out.
func TestLiveCollectWorkloadIdentityFederation(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{"iam.workloadIdentityPools": false, "iam.workloadIdentityPoolProviders": false}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
			t.Logf("%s: status=%s collected=%d reason=%q", c.Service, c.Status, c.Collected, c.Reason)
		}
	}
	for svc, seen := range want {
		if !seen {
			t.Errorf("missing completeness record for %s", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	pools, providers, noCond := 0, 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["gcp_type"] {
		case "wif_pool":
			pools++
		case "wif_provider":
			providers++
			if n.Attributes["has_attribute_condition"] == "false" {
				noCond++
			}
		}
	}
	t.Logf("project %s: %d WIF pools, %d providers (%d without an attribute condition)", project, pools, providers, noCond)
}

// TestLiveCollectOrgPolicy runs the GCP source end to end and checks the effective
// org-policy collector: it reads getEffectivePolicy for each curated security
// constraint, records orgpolicy.effectivePolicies without an unexpected Errored, maps
// each constraint to a control node with its effective enforcement, and leaks no
// access token. A caller without the permission is Denied; the API disabled is
// Unsupported; neither is a failure.
func TestLiveCollectOrgPolicy(t *testing.T) {
	ctx := context.Background()
	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var got collect.Completeness
	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "orgpolicy.effectivePolicies" {
			got, saw = c, true
			if c.Status == collect.Errored {
				t.Errorf("orgpolicy.effectivePolicies errored: %s", c.Reason)
			}
			t.Logf("orgpolicy.effectivePolicies: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing orgpolicy.effectivePolicies completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	enforced, notEnforced, unknown := 0, 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["gcp_type"] != "org_policy" {
			continue
		}
		switch n.Attributes["enforced"] {
		case "true":
			enforced++
		case "false":
			notEnforced++
		case "unknown":
			unknown++
		}
		t.Logf("%s enforced=%s", n.Attributes["constraint"], n.Attributes["enforced"])
	}
	_ = got
	t.Logf("project %s: org policy constraints enforced=%d not-enforced=%d unknown=%d", project, enforced, notEnforced, unknown)
}

// TestLiveCollectStorage runs the GCP source end to end and checks the Cloud
// Storage collector specifically: it lists buckets and reads their metadata and
// IAM (never object contents), records the two storage completeness records
// without an unexpected error, and leaks no access token. An empty project is an
// honest Complete/0.
func TestLiveCollectStorage(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawBuckets, sawIam bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "storage.buckets":
			sawBuckets = true
		case "storage.bucketIam":
			sawIam = true
		}
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s (%s)", c.Service, c.Reason)
		}
	}
	if !sawBuckets || !sawIam {
		t.Errorf("missing storage completeness records (buckets=%v iam=%v)", sawBuckets, sawIam)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	buckets := 0
	for _, n := range scan.Nodes {
		if n.Type == model.NodeDataStore {
			buckets++
		}
	}
	t.Logf("project %s: %d GCS buckets; completeness=%+v", project, buckets, scan.Completeness)
}

// TestLiveCollectInstances runs the GCP source end to end and checks the Compute
// Engine collector specifically: it enumerates every zone in one aggregatedList
// call (server-side aggregation, ADR-0020), records the single compute.instances
// completeness record without an unexpected error, maps any instances to compute
// nodes with a run-as edge to each attached service account, and leaks no access
// token. An empty project is an honest Complete/0. If some scopes were unreachable
// the record is Partial, which is a represented gap, not an error.
func TestLiveCollectInstances(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawInstances bool
	for _, c := range scan.Completeness {
		if c.Service == "compute.instances" {
			sawInstances = true
			if c.Status == collect.Errored {
				t.Errorf("compute.instances errored: %s", c.Reason)
			}
			t.Logf("compute.instances: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !sawInstances {
		t.Error("missing compute.instances completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	instances, runAs := 0, 0
	for _, n := range scan.Nodes {
		if n.Type == model.NodeCompute {
			instances++
		}
	}
	for _, l := range scan.Links {
		if l.Kind == model.EdgeAssumes {
			runAs++
		}
	}
	t.Logf("project %s: %d compute instances, %d assume edges (includes run-as); completeness=%+v",
		project, instances, runAs, scan.Completeness)
}

// TestLiveCollectNetworking runs the GCP source end to end and checks the VPC
// networking collector: it reads networks, subnetworks (via aggregatedList),
// firewalls, and routes, records one completeness record per resource without an
// unexpected error, maps them to nodes-and-attributes-only (no edges, per
// ADR-0019 §3), and leaks no access token. An empty project is an honest
// Complete/0; a disabled Compute API is Unsupported; an unreachable subnet scope is
// a Partial gap. None of these is a failure.
func TestLiveCollectNetworking(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{
		"compute.networks": false, "compute.subnetworks": false, "compute.firewalls": false, "compute.routes": false,
		"compute.routers": false, "compute.addresses": false, "compute.globalAddresses": false,
		"compute.forwardingRules": false, "compute.globalForwardingRules": false,
	}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
			t.Logf("%s: status=%s collected=%d reason=%q", c.Service, c.Status, c.Collected, c.Reason)
		}
	}
	for svc, saw := range want {
		if !saw {
			t.Errorf("missing %s completeness record", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	networks, controls := 0, 0
	for _, n := range scan.Nodes {
		switch n.Type {
		case model.NodeNetwork:
			networks++
		case model.NodeControl:
			controls++
		}
	}
	t.Logf("project %s: %d network nodes, %d control (firewall) nodes", project, networks, controls)
}

// TestLiveCollectCloudSQL runs the GCP source end to end and checks the Cloud SQL
// collector: it lists instances (metadata only, never database content or
// credentials), records the cloudsql.instances completeness record without an
// unexpected error, maps any instance to a data-store node with a run-as edge to its
// service agent, and leaks no access token. An empty project is an honest Complete/0;
// a disabled Cloud SQL Admin API is Unsupported; a denied read is Denied. None is a
// failure.
func TestLiveCollectCloudSQL(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "cloudsql.instances" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("cloudsql.instances errored: %s", c.Reason)
			}
			t.Logf("cloudsql.instances: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing cloudsql.instances completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	instances := 0
	for _, n := range scan.Nodes {
		if n.Attributes["database_version"] != "" {
			instances++
		}
	}
	t.Logf("project %s: %d Cloud SQL instances; completeness=%+v", project, instances, scan.Completeness)
}

// TestLiveCollectCloudKMS runs the GCP source end to end and checks the Cloud KMS
// collector: it fans out over locations and key rings to list crypto keys (metadata
// only, never key material), records the cloudkms.cryptoKeys completeness record
// without an unexpected error, maps any key to a control node, and leaks no access
// token. An empty project is an honest Complete/0; a disabled Cloud KMS API is
// Unsupported; a denied read is Denied; an unreadable ring is a Partial gap. None is a
// failure.
func TestLiveCollectCloudKMS(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "cloudkms.cryptoKeys" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("cloudkms.cryptoKeys errored: %s", c.Reason)
			}
			t.Logf("cloudkms.cryptoKeys: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing cloudkms.cryptoKeys completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	keys := 0
	for _, n := range scan.Nodes {
		if n.Attributes["resource_name"] != "" && strings.Contains(n.Attributes["resource_name"], "/cryptoKeys/") {
			keys++
		}
	}
	t.Logf("project %s: %d Cloud KMS crypto keys", project, keys)
}

// TestLiveCollectLogging runs the GCP source end to end and checks the logging
// collector: it lists log sinks and log buckets (configuration only, never log
// entries), records the logging.sinks and logging.buckets completeness records without
// an unexpected error, maps them to control nodes, and leaks no access token. An empty
// project is an honest Complete/0; a disabled Logging API is Unsupported; a denied read
// is Denied. None is a failure.
func TestLiveCollectLogging(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{"logging.sinks": false, "logging.buckets": false}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
			t.Logf("%s: status=%s collected=%d reason=%q", c.Service, c.Status, c.Collected, c.Reason)
		}
	}
	for svc, saw := range want {
		if !saw {
			t.Errorf("missing %s completeness record", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	sinks, buckets := 0, 0
	for _, n := range scan.Nodes {
		if strings.Contains(n.NativeID, "//logging.googleapis.com/") {
			if strings.Contains(n.NativeID, "/sinks/") {
				sinks++
			} else if strings.Contains(n.NativeID, "/buckets/") {
				buckets++
			}
		}
	}
	t.Logf("project %s: %d log sinks, %d log buckets", project, sinks, buckets)
}

// TestLiveCollectSCC runs the GCP source end to end and checks the Security Command
// Center collector: it lists the registered security sources (never individual
// findings), records the scc.sources completeness record without an unexpected error,
// maps any source to a control node, and leaks no access token. A project without
// Security Command Center activated surfaces as Denied or Unsupported, an empty project
// as Complete/0; none is a failure.
func TestLiveCollectSCC(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "scc.sources" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("scc.sources errored: %s", c.Reason)
			}
			t.Logf("scc.sources: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing scc.sources completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	sources := 0
	for _, n := range scan.Nodes {
		if strings.Contains(n.NativeID, "//securitycenter.googleapis.com/") {
			sources++
		}
	}
	t.Logf("project %s: %d SCC sources", project, sources)
}

// TestLiveCollectHierarchy runs the GCP source end to end and checks the resource
// hierarchy collector: it reads the project and walks its parent chain (read-only
// projects.get/folders.get/organizations.get, never a write), records the
// resourcemanager.hierarchy completeness without an unexpected error, and leaks no
// access token. A standalone project or a full chain is Complete; a denied ancestor is
// Partial; a disabled API is Unsupported. None is a failure.
func TestLiveCollectHierarchy(t *testing.T) {
	ctx := context.Background()

	project, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable GCP credentials in this environment: %v", err)
	}
	if project == "" {
		t.Skip("the credential has no associated default project")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "resourcemanager.hierarchy" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("resourcemanager.hierarchy errored: %s", c.Reason)
			}
			t.Logf("resourcemanager.hierarchy: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing resourcemanager.hierarchy completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "ya29.") {
			t.Errorf("evidence may contain an access token: %s", e.Operation)
		}
	}
	orgNodes := 0
	var projParent string
	for _, n := range scan.Nodes {
		if n.Attributes["hierarchy_type"] == "folder" || n.Attributes["hierarchy_type"] == "organization" {
			orgNodes++
		}
		if n.Type == model.NodeProject && n.NativeID == project {
			projParent = n.Attributes["parent_id"]
		}
	}
	t.Logf("project %s: parent_id=%q, %d ancestor nodes", project, projParent, orgNodes)
}
