//go:build live

// Run against a disposable Azure test tenant (ADR-0016 §3, ADR-0018) whose
// service principal is granted the read-only Microsoft Graph application
// permissions User.Read.All, Group.Read.All, and Application.Read.All:
//
//	AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
//	  go test -tags live -run TestLiveCollectEntraIdentities -v ./providers/azure/
//
// It drives the real Source, so it also exercises the single-credential
// resolution. It lives in providers/azure (not providers/azure/collect) for the
// same reason the AWS live test does: providers/azure depends on
// providers/azure/collect for the collector factory.
package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveCollectEntraIdentities resolves the Azure identity once, builds the
// Entra collector from that credential, runs it, and prints what it found. It
// proves the source authenticates, the collector paginates and maps real Entra
// data over plain-HTTP Graph, and that the evidence carries no leaked token.
func TestLiveCollectEntraIdentities(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	// The tenant node is always emitted; a real collection also finds directory
	// objects when the permissions are granted.
	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collection errored: %s (%s)", c.Service, c.Reason)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") { // a JWT header prefix
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}

	// GM-PERM-1 live check: the group-member read uses Group.Read.All (the app holds
	// it), not the removed GroupMember.ReadBasic.All. The first time the tenant has a
	// group, the membership pass runs; it must succeed (Complete/Partial), never
	// Denied, which would mean Group.Read.All did not in fact cover the member read.
	var groups, members collect.Completeness
	var sawGroups, sawMembers bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "entra.groups":
			groups, sawGroups = c, true
		case "entra.groupMembers":
			members, sawMembers = c, true
		}
	}
	if sawGroups && groups.Collected > 0 {
		if !sawMembers {
			t.Errorf("tenant has %d groups but no entra.groupMembers record: the membership pass did not run", groups.Collected)
		} else if members.Status == collect.Denied {
			t.Errorf("entra.groupMembers Denied with Group.Read.All held: the member read needs a permission the app lacks (GM-PERM-1 assumption wrong): %s", members.Reason)
		} else {
			t.Logf("GM-PERM-1 verified live: %d groups, entra.groupMembers status=%s (Group.Read.All covers the member read)", groups.Collected, members.Status)
		}
	} else {
		t.Logf("GM-PERM-1 not yet live-exercised: tenant has 0 groups, so the member read did not run")
	}

	t.Logf("tenant %s: collected %d nodes, %d evidence envelopes; completeness=%+v",
		tenant, len(scan.Nodes), len(scan.Envelopes), scan.Completeness)
}

// TestLiveCollectSecurityDefaults runs the Azure source end to end and checks the
// security defaults collector: it reads the tenant's security defaults enforcement
// policy and records entra.securityDefaults, emitting a control node with
// security_defaults_enabled, and leaks no token. Security defaults is available on
// every tenant regardless of license, so this returns real data.
func TestLiveCollectSecurityDefaults(t *testing.T) {
	ctx := context.Background()
	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "entra.securityDefaults" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("entra.securityDefaults errored: %s", c.Reason)
			}
			t.Logf("entra.securityDefaults: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing entra.securityDefaults completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	for _, n := range scan.Nodes {
		if n.Attributes["azure_type"] == "security_defaults" {
			t.Logf("security_defaults_enabled=%s", n.Attributes["security_defaults_enabled"])
		}
	}
}

// TestLiveCollectConditionalAccess runs the Azure source end to end and checks the
// Conditional Access collector: it reads the CA policies and records
// entra.conditionalAccess. On a tenant without an Entra ID P1/P2 license (an empty
// list or a licensing error) it must be Unsupported, never Complete and never a pass;
// with real policies it is Complete. It leaks no token.
func TestLiveCollectConditionalAccess(t *testing.T) {
	ctx := context.Background()
	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	var got collect.Completeness
	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "entra.conditionalAccess" {
			got, saw = c, true
			t.Logf("entra.conditionalAccess: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing entra.conditionalAccess completeness record")
	}
	// On an unlicensed tenant CA must never read as Complete (that would imply "no CA
	// gaps"); it is Unsupported. On a licensed tenant with policies it is Complete.
	if got.Status == collect.Complete && got.Collected == 0 {
		t.Errorf("conditional access Complete with 0 policies is forbidden (must be Unsupported): %+v", got)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
}

// TestLiveCollectAppCredentials runs the Azure source end to end and checks the
// application credential-expiry collector: it lists the tenant's app registrations
// over Graph and maps each credential (certificate or client secret) to a
// credential node with its expiry facts, records entra.appCredentials without an
// unexpected error, and, structurally, leaks neither a token nor the secret-adjacent
// passwordCredentials "hint". The test tenant's own app registration carries a real
// certificate credential, so this exercises live parsing, not just a fixture. A
// caller without Application.Read.All surfaces as Denied, never an empty-complete.
func TestLiveCollectAppCredentials(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "entra.appCredentials" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("entra.appCredentials errored: %s", c.Reason)
			}
			t.Logf("entra.appCredentials: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing entra.appCredentials completeness record")
	}
	for _, e := range scan.Envelopes {
		body := string(e.Response)
		if strings.Contains(body, "eyJ") { // a JWT header prefix
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
		if e.Operation == "entra.appCredentials" && (strings.Contains(body, `"hint"`) || strings.Contains(body, "secretText")) {
			t.Errorf("app-credential evidence contains a secret-adjacent field: %s", body)
		}
	}
	apps, creds, expired := 0, 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["azure_type"] {
		case "app_registration":
			apps++
		case "app_credential":
			creds++
			if n.Attributes["expired"] == "true" {
				expired++
			}
		}
	}
	t.Logf("tenant %s: %d app registrations, %d credentials (%d expired)", tenant, apps, creds, expired)
}

// TestLiveCollectAppRoleAssignments runs the Azure source end to end and checks the
// app-role assignment collector: it reads the service-principal app-role catalog and
// each principal's assignments over Graph, resolving each appRoleId to its value
// from the resource SP's own appRoles, and records entra.appRoleCatalog and
// entra.appRoleAssignments without an unexpected error and no leaked token. The test
// tenant's own app registration holds real Microsoft Graph application permissions,
// so this exercises live name resolution, not just a fixture. A caller without
// Application.Read.All surfaces as Denied, never an empty-complete.
func TestLiveCollectAppRoleAssignments(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{"entra.appRoleCatalog": false, "entra.appRoleAssignments": false}
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
		if strings.Contains(string(e.Response), "eyJ") { // a JWT header prefix
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	grants, resolved := 0, 0
	for _, n := range scan.Nodes {
		if n.Type == model.NodeRole && n.Attributes["grant_type"] == "application" {
			grants++
			if n.Attributes["resolved"] == "true" {
				resolved++
			}
		}
	}
	t.Logf("tenant %s: %d application-permission role nodes (%d name-resolved)", tenant, grants, resolved)
}

// TestLiveCollectStorage runs the Azure source end to end and checks the storage
// collector: it lists storage accounts across the accessible subscriptions and maps
// each to a data-store node with its security posture, records the two completeness
// records without an unexpected error, and leaks no token. It deliberately surfaces
// the real permission outcome for storage.accounts (Complete, Denied, or empty) so
// whether the app actually has Microsoft.Storage/storageAccounts/read is reported,
// not assumed either direction.
func TestLiveCollectStorage(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawSubs, sawAccounts bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "storage.subscriptions":
			sawSubs = true
		case "storage.accounts":
			sawAccounts = true
			// Report the real outcome: Complete (with N accounts), Denied (the app
			// lacks storage read), or a represented gap - all acceptable, none assumed.
			t.Logf("storage.accounts@%s: status=%s collected=%d reason=%q", c.Scope.Resource, c.Status, c.Collected, c.Reason)
		}
		if c.Status == collect.Errored && (c.Service == "storage.subscriptions" || c.Service == "storage.accounts") {
			t.Errorf("%s errored: %s", c.Service, c.Reason)
		}
	}
	if !sawSubs || !sawAccounts {
		t.Errorf("missing storage completeness records (subs=%v accounts=%v)", sawSubs, sawAccounts)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") { // a JWT header prefix
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	accounts := 0
	for _, n := range scan.Nodes {
		if n.Attributes["azure_type"] == "storage_account" {
			accounts++
		}
	}
	t.Logf("tenant %s: %d storage-account nodes", tenant, accounts)
}

// TestLiveCollectCompute runs the Azure source end to end and checks the compute
// collector: it lists virtual machines across the accessible subscriptions, maps
// each to a compute node with the run-as edge to its managed identity, records the
// two completeness records without an unexpected error, and leaks no token. It
// surfaces the real permission outcome for compute.virtualMachines so whether the
// app actually has Microsoft.Compute/virtualMachines/read is reported, not assumed.
func TestLiveCollectCompute(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawSubs, sawVMs bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "compute.subscriptions":
			sawSubs = true
		case "compute.virtualMachines":
			sawVMs = true
			t.Logf("compute.virtualMachines@%s: status=%s collected=%d reason=%q", c.Scope.Resource, c.Status, c.Collected, c.Reason)
		}
		if c.Status == collect.Errored && (c.Service == "compute.subscriptions" || c.Service == "compute.virtualMachines") {
			t.Errorf("%s errored: %s", c.Service, c.Reason)
		}
	}
	if !sawSubs || !sawVMs {
		t.Errorf("missing compute completeness records (subs=%v vms=%v)", sawSubs, sawVMs)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	vms, runAs := 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["azure_type"] == "virtual_machine" {
			vms++
		}
	}
	for _, l := range scan.Links {
		if l.Kind == model.EdgeAssumes {
			runAs++
		}
	}
	t.Logf("tenant %s: %d VM nodes, %d assume edges (includes VM run-as)", tenant, vms, runAs)
}

// TestLiveCollectNetworking runs the Azure source end to end and checks the network
// collector: it lists virtual networks (with subnets), network security groups (with
// rules), public IP addresses, and network interfaces across the accessible
// subscriptions, records four completeness records per subscription without an
// unexpected error, and leaks no token. It surfaces the real permission outcome for
// each resource type so whether the app actually has the Microsoft.Network reads is
// reported, not assumed, and reports the NSG dual-attachment ground truth: whether a
// real NSG-to-subnet-and-NIC association recorded on every side, or an honest empty.
func TestLiveCollectNetworking(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{
		"network.virtualNetworks": false, "network.networkSecurityGroups": false,
		"network.publicIPAddresses": false, "network.networkInterfaces": false,
	}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			t.Logf("%s@%s: status=%s collected=%d reason=%q", c.Service, c.Scope.Resource, c.Status, c.Collected, c.Reason)
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
		}
	}
	for svc, seen := range want {
		if !seen {
			t.Errorf("missing completeness record for %s", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}

	// NSG dual-attachment ground truth: count NSGs that named a subnet or a NIC, and
	// count subnets and NICs that named their NSG. On a tenant with a real
	// association these are non-zero and consistent; on an empty tenant this is an
	// honest zero on every side, never a fabricated edge.
	nsgWithSubnet, nsgWithNIC, subnetWithNSG, nicWithNSG := 0, 0, 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["azure_type"] {
		case "network_security_group":
			if n.Attributes["associated_subnets"] != "" {
				nsgWithSubnet++
			}
			if n.Attributes["associated_nics"] != "" {
				nsgWithNIC++
			}
		case "subnet":
			if n.Attributes["nsg_id"] != "" {
				subnetWithNSG++
			}
		case "network_interface":
			if n.Attributes["nsg_id"] != "" {
				nicWithNSG++
			}
		}
	}
	t.Logf("NSG dual-attachment: nsgs naming a subnet=%d, nsgs naming a nic=%d; subnets naming an nsg=%d, nics naming an nsg=%d",
		nsgWithSubnet, nsgWithNIC, subnetWithNSG, nicWithNSG)
}

// TestLiveCollectKeyVault runs the Azure source end to end and checks the key vault
// collector: it lists vaults across the accessible subscriptions, maps each to a
// control node with its authorization mode and network and access-policy posture,
// records the completeness records without an unexpected error, and leaks no token. It
// surfaces the real permission outcome for keyvault.vaults and asserts, structurally,
// that no data-plane key, secret, or certificate value appears in the evidence.
func TestLiveCollectKeyVault(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var sawSubs, sawVaults bool
	for _, c := range scan.Completeness {
		switch c.Service {
		case "keyvault.subscriptions":
			sawSubs = true
		case "keyvault.vaults":
			sawVaults = true
			t.Logf("keyvault.vaults@%s: status=%s collected=%d reason=%q", c.Scope.Resource, c.Status, c.Collected, c.Reason)
		}
		if c.Status == collect.Errored && (c.Service == "keyvault.subscriptions" || c.Service == "keyvault.vaults") {
			t.Errorf("%s errored: %s", c.Service, c.Reason)
		}
	}
	if !sawSubs || !sawVaults {
		t.Errorf("missing keyvault completeness records (subs=%v vaults=%v)", sawSubs, sawVaults)
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	vaults, rbac, policyMode := 0, 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["azure_type"] != "key_vault" {
			continue
		}
		vaults++
		switch n.Attributes["authorization_mode"] {
		case "rbac":
			rbac++
		case "access_policies":
			policyMode++
		}
	}
	t.Logf("tenant %s: %d key vault nodes (%d rbac, %d access-policy mode)", tenant, vaults, rbac, policyMode)
}

// TestLiveCollectDatabases runs the Azure source end to end and checks the database
// collector across all four engines (SQL servers, PostgreSQL and MySQL flexible
// servers, Cosmos accounts): it lists each across the accessible subscriptions,
// records a completeness record per engine without an unexpected error, and leaks no
// token. It surfaces the real permission outcome per engine so whether each
// Microsoft.* read is granted is reported, not assumed, and counts any managed-identity
// run-as edges emitted from a real database resource.
func TestLiveCollectDatabases(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{
		"database.sqlServers": false, "database.postgresqlServers": false,
		"database.mysqlServers": false, "database.cosmosAccounts": false,
	}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			t.Logf("%s@%s: status=%s collected=%d reason=%q", c.Service, c.Scope.Resource, c.Status, c.Collected, c.Reason)
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
		}
	}
	for svc, seen := range want {
		if !seen {
			t.Errorf("missing completeness record for %s", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	stores, runAs := 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["engine"] {
		case "sql", "postgresql", "mysql", "cosmosdb":
			stores++
		}
	}
	for _, l := range scan.Links {
		if l.Kind == model.EdgeAssumes {
			runAs++
		}
	}
	t.Logf("tenant %s: %d database nodes, %d assume edges total (includes DB run-as)", tenant, stores, runAs)
}

// TestLiveCollectLogging runs the Azure source end to end and checks the logging
// collector: it lists Log Analytics workspaces and the subscription diagnostic
// settings across the accessible subscriptions, records the completeness records
// without an unexpected error, and leaks no token. It surfaces the real permission
// outcome for each so whether the two Microsoft.* reads are granted is reported, not
// assumed, and counts the workspace and diagnostic-setting nodes found.
func TestLiveCollectLogging(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{"logging.workspaces": false, "logging.diagnosticSettings": false}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			t.Logf("%s@%s: status=%s collected=%d reason=%q", c.Service, c.Scope.Resource, c.Status, c.Collected, c.Reason)
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
		}
	}
	for svc, seen := range want {
		if !seen {
			t.Errorf("missing completeness record for %s", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	workspaces, diagSettings := 0, 0
	for _, n := range scan.Nodes {
		switch n.Attributes["azure_type"] {
		case "log_analytics_workspace":
			workspaces++
		case "diagnostic_setting":
			diagSettings++
		}
	}
	t.Logf("tenant %s: %d workspace nodes, %d subscription diagnostic-setting nodes", tenant, workspaces, diagSettings)
}

// TestLiveCollectDefender runs the Azure source end to end and checks the Defender for
// Cloud collector: it reads the Defender plans (pricings) and the auto-provisioning
// setting across the accessible subscriptions, records the completeness records
// without an unexpected error, and leaks no token. It surfaces the real permission
// outcome per resource and reports the per-plan tiers found, the actual
// threat-protection posture, not an assumption.
func TestLiveCollectDefender(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	want := map[string]bool{"defender.pricings": false, "defender.autoProvisioning": false}
	for _, c := range scan.Completeness {
		if _, ok := want[c.Service]; ok {
			want[c.Service] = true
			t.Logf("%s@%s: status=%s collected=%d reason=%q", c.Service, c.Scope.Resource, c.Status, c.Collected, c.Reason)
			if c.Status == collect.Errored {
				t.Errorf("%s errored: %s", c.Service, c.Reason)
			}
		}
	}
	for svc, seen := range want {
		if !seen {
			t.Errorf("missing completeness record for %s", svc)
		}
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	standard, free := 0, 0
	for _, n := range scan.Nodes {
		if n.Attributes["azure_type"] != "defender_plan" {
			continue
		}
		switch n.Attributes["pricing_tier"] {
		case "Standard":
			standard++
		case "Free":
			free++
		}
		t.Logf("defender plan %s: tier=%s", n.Attributes["plan"], n.Attributes["pricing_tier"])
	}
	t.Logf("tenant %s: Defender plans %d Standard, %d Free", tenant, standard, free)
}

// TestLiveCollectManagementGroups runs the Azure source end to end and checks the
// management-group hierarchy collector: it gets the tenant-root management group with
// its full child tree (read-only, no write), records the management.hierarchy
// completeness without an unexpected error, maps management groups and subscriptions to
// nodes, and leaks no token. A caller without management-group RBAC surfaces as Denied,
// a tenant with only the root group as Complete with the root alone. None is a failure.
func TestLiveCollectManagementGroups(t *testing.T) {
	ctx := context.Background()

	tenant, collectors, err := NewSource().Collectors(ctx, nil)
	if err != nil {
		t.Skipf("no usable Azure credentials in this environment: %v", err)
	}
	if tenant == "" {
		t.Fatal("resolved an empty tenant")
	}

	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	var saw bool
	for _, c := range scan.Completeness {
		if c.Service == "management.hierarchy" {
			saw = true
			if c.Status == collect.Errored {
				t.Errorf("management.hierarchy errored: %s", c.Reason)
			}
			t.Logf("management.hierarchy: status=%s collected=%d reason=%q", c.Status, c.Collected, c.Reason)
		}
	}
	if !saw {
		t.Error("missing management.hierarchy completeness record")
	}
	for _, e := range scan.Envelopes {
		if strings.Contains(string(e.Response), "eyJ") {
			t.Errorf("evidence may contain a token: %s", e.Operation)
		}
	}
	mgs := 0
	for _, n := range scan.Nodes {
		if n.Attributes["hierarchy_type"] == "management_group" {
			mgs++
		}
	}
	t.Logf("tenant %s: %d management-group nodes", tenant, mgs)
}
