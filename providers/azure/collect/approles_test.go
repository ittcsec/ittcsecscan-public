package collect

import (
	"context"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// The catalog lists a resource SP (Microsoft Graph) carrying two app roles and an
// app principal with none; the app principal holds two assignments: one resolvable
// (Directory.ReadWrite.All) and one whose GUID is absent from the catalog.
const (
	appRoleCatalog = `{"value":[
		{"id":"sp-graph","appId":"graph-app","displayName":"Microsoft Graph","appRoles":[
			{"id":"role-user-read","value":"User.Read.All","displayName":"Read all users"},
			{"id":"role-dir-rw","value":"Directory.ReadWrite.All","displayName":"Read and write directory data"}]},
		{"id":"sp-app","appId":"app-1","displayName":"My App","appRoles":[]}]}`
	appRoleAssignmentsForApp = `{"value":[
		{"id":"a1","principalId":"sp-app","resourceId":"sp-graph","resourceDisplayName":"Microsoft Graph","appRoleId":"role-dir-rw"},
		{"id":"a2","principalId":"sp-app","resourceId":"sp-graph","resourceDisplayName":"Microsoft Graph","appRoleId":"role-unknown-guid"}]}`
)

func runAppRoles(t *testing.T, api graphAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newAppRoleAssignmentCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func roleNode(s collect.Scan, nativeID string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeRole && n.NativeID == nativeID {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestAppRoleAssignmentResolvesNames proves app-role GUIDs are resolved to their
// value from the resource SP's own appRoles catalog (never a static table), the
// grant is an assumes edge from principal to role, and an unresolvable GUID is
// recorded verbatim with resolved=false rather than guessed.
func TestAppRoleAssignmentResolvesNames(t *testing.T) {
	s := runAppRoles(t, &stubGraph{bodies: map[string]string{
		"servicePrincipals?$select": appRoleCatalog,
		"sp-app/appRoleAssignments": appRoleAssignmentsForApp,
	}})

	if c := completenessOf(s, "entra.appRoleCatalog"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("entra.appRoleCatalog = %+v, want complete/2", c)
	}
	if c := completenessOf(s, "entra.appRoleAssignments"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("entra.appRoleAssignments = %+v, want complete/2", c)
	}

	resolved, ok := roleNode(s, "sp-graph/role-dir-rw")
	if !ok {
		t.Fatal("resolved role node not emitted")
	}
	if resolved.Name != "Directory.ReadWrite.All" || resolved.Attributes["permission"] != "Directory.ReadWrite.All" || resolved.Attributes["resolved"] != "true" {
		t.Errorf("resolved role facts = name=%q %+v", resolved.Name, resolved.Attributes)
	}
	// resource_app_id is the resource SP's appId (Microsoft Graph in production), from the
	// catalog pass, so a rule can match the resource API by appId not display name.
	if resolved.Attributes["resource_app_id"] != "graph-app" {
		t.Errorf("resolved role resource_app_id = %q, want graph-app", resolved.Attributes["resource_app_id"])
	}

	unknown, ok := roleNode(s, "sp-graph/role-unknown-guid")
	if !ok {
		t.Fatal("unresolved role node not emitted")
	}
	if unknown.Name != "role-unknown-guid" || unknown.Attributes["resolved"] != "false" || unknown.Attributes["permission"] != "" {
		t.Errorf("unresolved role should carry the raw GUID and resolved=false, never a guess: name=%q %+v", unknown.Name, unknown.Attributes)
	}

	// The grant is an assumes edge from the app principal to the role.
	found := false
	for _, l := range s.Links {
		if l.Kind == model.EdgeAssumes && l.SourceNativeID == "sp-app" && l.TargetNativeID == "sp-graph/role-dir-rw" {
			found = true
			if l.Conditions["grant_type"] != "application" {
				t.Errorf("grant edge missing grant_type=application: %+v", l.Conditions)
			}
		}
	}
	if !found {
		t.Errorf("no assumes grant edge sp-app -> sp-graph/role-dir-rw: %+v", s.Links)
	}
}

// TestAppRoleAssignmentDeniedCatalogIsNotCompleteAssignments proves that when the
// catalog read is denied (so the principal set is unknown), the assignments
// enumeration is not reported Complete, and the catalog denial is its own gap, so
// an operator is never told "this tenant grants no app permissions" on a denial.
func TestAppRoleAssignmentDeniedCatalogIsNotCompleteAssignments(t *testing.T) {
	s := runAppRoles(t, &stubGraph{failSub: "servicePrincipals?$select", failWith: &azureError{status: 403, body: "denied"}})
	if statusOf(s, "entra.appRoleCatalog") != collect.Denied {
		t.Errorf("catalog status = %s, want denied", statusOf(s, "entra.appRoleCatalog"))
	}
	if st := statusOf(s, "entra.appRoleAssignments"); st == collect.Complete {
		t.Errorf("assignments must not be Complete when the catalog was denied; got %s", st)
	}
	if nodesByType(s)[model.NodeRole] != 0 {
		t.Error("no role nodes should be emitted when the catalog is denied")
	}
}

// TestAppRoleAssignmentPerPrincipalDenialIsGap proves that one principal's denied
// assignment read is a recorded Partial reason and does not abort the catalog's
// completeness.
func TestAppRoleAssignmentPerPrincipalDenialIsGap(t *testing.T) {
	s := runAppRoles(t, &stubGraph{
		bodies:   map[string]string{"servicePrincipals?$select": appRoleCatalog},
		failSub:  "appRoleAssignments",
		failWith: &azureError{status: 403, body: "denied"},
	})
	if statusOf(s, "entra.appRoleCatalog") != collect.Complete {
		t.Errorf("catalog should still be Complete: %s", statusOf(s, "entra.appRoleCatalog"))
	}
	if c := completenessOf(s, "entra.appRoleAssignments"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("assignments = %+v, want partial/denied", c)
	}
}
