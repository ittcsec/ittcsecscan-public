package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	sqlServerID = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Sql/servers/sql1"
	pgServerID  = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg1"
	myServerID  = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.DBforMySQL/flexibleServers/my1"
	cosmosID    = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.DocumentDB/databaseAccounts/cos1"
)

// oneSQLServer is a Microsoft.Sql/servers list page (with administrators expanded):
// one server with a system-assigned managed identity, an Azure AD administrator, a
// customer-managed key, and a TLS floor.
const oneSQLServer = `{"value":[
	{"id":"` + sqlServerID + `","name":"sql1","location":"eastus","tags":{"env":"prod"},
	 "identity":{"type":"SystemAssigned","principalId":"sql-sys-principal"},
	 "properties":{
	   "administratorLogin":"sqladmin","version":"12.0","state":"Ready",
	   "fullyQualifiedDomainName":"sql1.database.windows.net",
	   "publicNetworkAccess":"Enabled","minimalTlsVersion":"1.2","restrictOutboundNetworkAccess":"Disabled",
	   "keyId":"https://kv1.vault.azure.net/keys/cmk/abc",
	   "administrators":{"login":"dbagroup","sid":"aad-admin-guid","principalType":"Group","azureADOnlyAuthentication":true}}}
]}`

// onePostgreSQL is a PostgreSQL flexibleServers list page: AAD auth on, CMK, HA, geo
// backup, a delegated subnet, and a user-assigned managed identity.
const onePostgreSQL = `{"value":[
	{"id":"` + pgServerID + `","name":"pg1","location":"eastus",
	 "identity":{"type":"UserAssigned","userAssignedIdentities":{"/subscriptions/sub-1/uai1":{"principalId":"pg-uai-principal"}}},
	 "properties":{
	   "administratorLogin":"pgadmin","version":"16","state":"Ready",
	   "fullyQualifiedDomainName":"pg1.postgres.database.azure.com",
	   "network":{"publicNetworkAccess":"Disabled","delegatedSubnetResourceId":"` + subnetID + `"},
	   "authConfig":{"activeDirectoryAuth":"Enabled","passwordAuth":"Disabled"},
	   "dataEncryption":{"type":"AzureKeyVault","primaryKeyURI":"https://kv1.vault.azure.net/keys/pgcmk/def"},
	   "highAvailability":{"mode":"ZoneRedundant"},
	   "backup":{"geoRedundantBackup":"Enabled"},
	   "storage":{"autoGrow":"Enabled","storageSizeGB":512}}}
]}`

// oneMySQL is a MySQL flexibleServers list page: no authConfig (MySQL has none),
// system-managed encryption, HA disabled.
const oneMySQL = `{"value":[
	{"id":"` + myServerID + `","name":"my1","location":"eastus",
	 "properties":{
	   "administratorLogin":"myadmin","version":"8.0.21","state":"Ready",
	   "fullyQualifiedDomainName":"my1.mysql.database.azure.com",
	   "network":{"publicNetworkAccess":"Enabled"},
	   "dataEncryption":{"type":"SystemManaged"},
	   "highAvailability":{"mode":"Disabled"},
	   "backup":{"geoRedundantBackup":"Disabled"},
	   "storage":{"autoGrow":"Enabled","storageSizeGB":128}}}
]}`

// oneCosmos is a Microsoft.DocumentDB/databaseAccounts list page: local auth disabled,
// a vnet firewall with an ip rule and a subnet rule, and a system-assigned identity.
const oneCosmos = `{"value":[
	{"id":"` + cosmosID + `","name":"cos1","location":"eastus","kind":"GlobalDocumentDB",
	 "identity":{"type":"SystemAssigned","principalId":"cosmos-sys-principal"},
	 "properties":{
	   "documentEndpoint":"https://cos1.documents.azure.com:443/",
	   "databaseAccountOfferType":"Standard",
	   "publicNetworkAccess":"Enabled","disableLocalAuth":true,"disableKeyBasedMetadataWriteAccess":true,
	   "isVirtualNetworkFilterEnabled":true,"enableAutomaticFailover":false,
	   "networkAclBypass":"AzureServices","minimalTlsVersion":"Tls12",
	   "ipRules":[{"ipAddressOrRange":"40.76.54.131"}],
	   "virtualNetworkRules":[{"id":"` + subnetID + `"}]}}
]}`

func databaseStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?":       subsOne,
		"Microsoft.Sql/servers": oneSQLServer,
		"DBforPostgreSQL":       onePostgreSQL,
		"DBforMySQL":            oneMySQL,
		"DocumentDB":            oneCosmos,
	}}
}

func runDatabase(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newDatabaseCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestDatabaseSQLServer proves an Azure SQL server becomes a data-store node with its
// posture, the CMK URI and AAD admin object id recorded as forward keys, and a run-as
// edge to its system-assigned managed identity.
func TestDatabaseSQLServer(t *testing.T) {
	s := runDatabase(t, databaseStub())

	n, ok := nodeNamed(s, model.NodeDataStore, sqlServerID)
	if !ok {
		t.Fatal("sql1 not keyed by its ARM resource id")
	}
	for k, want := range map[string]string{
		"azure_type": "sql_server", "engine": "sql", "version": "12.0", "state": "Ready",
		"administrator_login": "sqladmin", "public_network_access": "Enabled",
		"minimal_tls_version": "1.2", "cmk_key_uri": "https://kv1.vault.azure.net/keys/cmk/abc",
		"aad_admin_login": "dbagroup", "aad_admin_sid": "aad-admin-guid",
		"aad_only_authentication": "true", "tag:env": "prod",
	} {
		if n.Attributes[k] != want {
			t.Errorf("sql1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	if !hasRunAs(s, sqlServerID, "sql-sys-principal") {
		t.Error("missing run-as edge sql1 -> sql-sys-principal")
	}
	if _, ok := nodeNamed(s, model.NodeWorkload, "sql-sys-principal"); !ok {
		t.Error("managed identity not emitted as a workload node")
	}
	for _, forbidden := range []string{"is_public", "exposed", "compliant"} {
		if _, bad := n.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "database.sqlServers"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("database.sqlServers = %+v, want complete/1", c)
	}
}

// TestDatabasePostgreSQL proves a PostgreSQL flexible server maps its AAD auth config,
// CMK, delegated subnet join key, and a user-assigned run-as edge.
func TestDatabasePostgreSQL(t *testing.T) {
	s := runDatabase(t, databaseStub())

	n, ok := nodeNamed(s, model.NodeDataStore, pgServerID)
	if !ok {
		t.Fatal("pg1 not emitted")
	}
	for k, want := range map[string]string{
		"azure_type": "postgresql_flexible_server", "engine": "postgresql", "version": "16",
		"public_network_access": "Disabled", "active_directory_auth": "Enabled", "password_auth": "Disabled",
		"data_encryption_type": "AzureKeyVault", "cmk_key_uri": "https://kv1.vault.azure.net/keys/pgcmk/def",
		"high_availability_mode": "ZoneRedundant", "geo_redundant_backup": "Enabled",
		"delegated_subnet_id": subnetID, "storage_size_gb": "512",
	} {
		if n.Attributes[k] != want {
			t.Errorf("pg1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	if !hasRunAs(s, pgServerID, "pg-uai-principal") {
		t.Error("missing run-as edge pg1 -> pg-uai-principal (user-assigned)")
	}
}

// TestDatabaseMySQL proves a MySQL flexible server maps its shared flexible-server
// fields and, correctly, carries no AAD auth config (MySQL has none) and no run-as
// edge (no identity block).
func TestDatabaseMySQL(t *testing.T) {
	s := runDatabase(t, databaseStub())

	n, ok := nodeNamed(s, model.NodeDataStore, myServerID)
	if !ok {
		t.Fatal("my1 not emitted")
	}
	for k, want := range map[string]string{
		"azure_type": "mysql_flexible_server", "engine": "mysql", "version": "8.0.21",
		"public_network_access": "Enabled", "data_encryption_type": "SystemManaged",
		"high_availability_mode": "Disabled", "geo_redundant_backup": "Disabled", "storage_size_gb": "128",
	} {
		if n.Attributes[k] != want {
			t.Errorf("my1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	if _, bad := n.Attributes["active_directory_auth"]; bad {
		t.Error("MySQL must not carry an active_directory_auth fact")
	}
	for _, l := range s.Links {
		if l.SourceNativeID == myServerID {
			t.Errorf("my1 must have no run-as edge, got -> %s", l.TargetNativeID)
		}
	}
}

// TestDatabaseCosmos proves a Cosmos account maps its firewall and auth posture with
// the ip and subnet rules as facts, and a run-as edge to its system-assigned identity.
func TestDatabaseCosmos(t *testing.T) {
	s := runDatabase(t, databaseStub())

	n, ok := nodeNamed(s, model.NodeDataStore, cosmosID)
	if !ok {
		t.Fatal("cos1 not emitted")
	}
	for k, want := range map[string]string{
		"azure_type": "cosmosdb_account", "engine": "cosmosdb", "kind": "GlobalDocumentDB",
		"public_network_access": "Enabled", "disable_local_auth": "true",
		"disable_key_based_metadata_write": "true", "is_virtual_network_filter_enabled": "true",
		"enable_automatic_failover": "false", "network_acl_bypass": "AzureServices",
		"ip_rules": "40.76.54.131", "virtual_network_rules": subnetID,
	} {
		if n.Attributes[k] != want {
			t.Errorf("cos1 %s = %q, want %q", k, n.Attributes[k], want)
		}
	}
	if !hasRunAs(s, cosmosID, "cosmos-sys-principal") {
		t.Error("missing run-as edge cos1 -> cosmos-sys-principal")
	}
}

// TestDatabaseDeniedIsGap proves a denied read of one engine is a Denied gap that does
// not fail the run and does not block the other engines.
func TestDatabaseDeniedIsGap(t *testing.T) {
	api := databaseStub()
	api.failSub = "DocumentDB"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newDatabaseCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "database.cosmosAccounts") != collect.Denied {
		t.Errorf("database.cosmosAccounts = %s, want denied", statusOf(s, "database.cosmosAccounts"))
	}
	if _, ok := nodeNamed(s, model.NodeDataStore, cosmosID); ok {
		t.Error("a denied cosmos read must not emit an account node")
	}
	// The other engines still collected.
	if statusOf(s, "database.sqlServers") != collect.Complete {
		t.Errorf("sql servers should still be complete, got %s", statusOf(s, "database.sqlServers"))
	}
}

// TestDatabaseEmptyIsComplete proves an empty subscription is an honest Complete/0 for
// every engine.
func TestDatabaseEmptyIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne}}
	s := runDatabase(t, api)
	for _, svc := range []string{"database.sqlServers", "database.postgresqlServers", "database.mysqlServers", "database.cosmosAccounts"} {
		if c := completenessOf(s, svc); c.Status != collect.Complete || c.Collected != 0 {
			t.Errorf("%s = %+v, want complete/0", svc, c)
		}
	}
}

// TestDatabasePaginates proves nextLink is followed across pages.
func TestDatabasePaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"DocumentDB":      `{"value":[{"id":"` + cosmosID + `a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":             `{"value":[{"id":"` + cosmosID + `b","name":"b"}]}`,
	}}
	s := runDatabase(t, api)
	n := 0
	for _, node := range s.Nodes {
		if node.Attributes["engine"] == "cosmosdb" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("cosmos accounts across pages = %d, want 2", n)
	}
}

// TestDatabaseBudgetExhaustion proves the shared budget bounds the sweep.
func TestDatabaseBudgetExhaustion(t *testing.T) {
	c := newDatabaseCollector("tenant-1", databaseStub())
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "database.sqlServers"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("database.sqlServers = %+v, want partial budget-exhausted", got)
	}
}

// TestDatabaseEvidenceRedactsToken proves the evidence body is scrubbed.
func TestDatabaseEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":       subsOne,
		"Microsoft.Sql/servers": `{"value":[{"id":"` + sqlServerID + `","name":"` + token + `"}]}`,
	}}
	s := runDatabase(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}

// hasRunAs reports whether an assumes edge from source to target exists.
func hasRunAs(s collect.Scan, source, target string) bool {
	for _, l := range s.Links {
		if l.Kind == model.EdgeAssumes && l.SourceNativeID == source && l.TargetNativeID == target {
			return true
		}
	}
	return false
}
