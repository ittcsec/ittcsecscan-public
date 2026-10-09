package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	rootMGID     = "/providers/Microsoft.Management/managementGroups/tenant-1"
	platformMGID = "/providers/Microsoft.Management/managementGroups/Platform"
)

// mgTree is a managementGroups.get response with $expand=children&$recurse=true: the
// tenant root group, a child management group, and a subscription under it.
const mgTree = `{
	"id":"` + rootMGID + `","name":"tenant-1","type":"Microsoft.Management/managementGroups",
	"properties":{
		"tenantId":"tenant-1","displayName":"Tenant Root Group",
		"children":[
			{"id":"` + platformMGID + `","name":"Platform","type":"Microsoft.Management/managementGroups","displayName":"Platform",
			 "children":[
				{"id":"/subscriptions/sub-abc","name":"sub-abc","type":"/subscriptions","displayName":"Connectivity"}
			 ]}
		]
	}
}`

func mgStub() *stubARM {
	return &stubARM{bodies: map[string]string{"managementGroups": mgTree}}
}

func runMG(t *testing.T, tenant string, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newManagementGroupCollector(tenant, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

// TestMGWalksTree proves the recursive tree yields an organization node per management
// group (keyed by ARM id, hierarchy_type management_group) and a subscription node per
// subscription child (keyed by subscription id so it merges with other collectors),
// each carrying its parent as a forward-key id fact, with no synthesized edge.
func TestMGWalksTree(t *testing.T) {
	s := runMG(t, "tenant-1", mgStub())

	root, ok := nodeNamed(s, model.NodeOrganization, rootMGID)
	if !ok {
		t.Fatal("root management group not keyed by its ARM id")
	}
	for k, want := range map[string]string{
		"hierarchy_type": "management_group", "is_root": "true",
		"display_name": "Tenant Root Group", "tenant_id": "tenant-1",
	} {
		if root.Attributes[k] != want {
			t.Errorf("root %s = %q, want %q", k, root.Attributes[k], want)
		}
	}
	if _, has := root.Attributes["parent_id"]; has {
		t.Errorf("tenant root must have no parent_id, got %q", root.Attributes["parent_id"])
	}

	plat, ok := nodeNamed(s, model.NodeOrganization, platformMGID)
	if !ok {
		t.Fatal("Platform management group not emitted")
	}
	if plat.Attributes["parent_id"] != rootMGID || plat.Attributes["hierarchy_type"] != "management_group" {
		t.Errorf("Platform attrs = %+v", plat.Attributes)
	}

	sub, ok := nodeNamed(s, model.NodeSubscription, "sub-abc")
	if !ok {
		t.Fatal("subscription not keyed by its subscription id (so it would not merge with other collectors)")
	}
	if sub.Attributes["parent_id"] != platformMGID {
		t.Errorf("subscription parent_id = %q, want %q", sub.Attributes["parent_id"], platformMGID)
	}
	for _, forbidden := range []string{"compliant", "inherited_roles"} {
		if _, bad := plat.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "management.hierarchy"); c.Status != collect.Complete || c.Collected != 3 {
		t.Errorf("management.hierarchy = %+v, want complete/3", c)
	}
}

// TestMGDeniedIsGap proves a denied read (the caller lacks management-group RBAC) is a
// Denied gap, never a pass, and emits no node.
func TestMGDeniedIsGap(t *testing.T) {
	api := &stubARM{failSub: "managementGroups", failWith: &azureError{status: 403, body: "AuthorizationFailed"}}
	var s collect.Scan
	if err := newManagementGroupCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "management.hierarchy") != collect.Denied {
		t.Errorf("management.hierarchy = %s, want denied", statusOf(s, "management.hierarchy"))
	}
	if len(s.Nodes) != 0 {
		t.Errorf("nodes = %d, want 0", len(s.Nodes))
	}
}

// TestMGNoTenantIsUnsupported proves an empty tenant id is an Unsupported gap.
func TestMGNoTenantIsUnsupported(t *testing.T) {
	s := runMG(t, "", mgStub())
	if c := completenessOf(s, "management.hierarchy"); c.Status != collect.Unsupported {
		t.Errorf("management.hierarchy = %+v, want unsupported", c)
	}
}

// TestMGNestedParent proves a non-root group records its parent management group.
func TestMGNestedParent(t *testing.T) {
	body := `{"id":"` + platformMGID + `","name":"Platform","type":"Microsoft.Management/managementGroups",
		"properties":{"tenantId":"tenant-1","displayName":"Platform",
		"details":{"parent":{"id":"` + rootMGID + `","name":"tenant-1","displayName":"Tenant Root Group"}}}}`
	s := runMG(t, "tenant-1", &stubARM{bodies: map[string]string{"managementGroups": body}})
	n, _ := nodeNamed(s, model.NodeOrganization, platformMGID)
	if n.Attributes["parent_id"] != rootMGID {
		t.Errorf("parent_id = %q, want %q", n.Attributes["parent_id"], rootMGID)
	}
	if n.Attributes["is_root"] != "false" {
		t.Errorf("is_root = %q, want false", n.Attributes["is_root"])
	}
}

// TestMGEvidenceRedactsToken proves the evidence body is scrubbed.
func TestMGEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	body := `{"id":"` + rootMGID + `","name":"` + token + `","properties":{"displayName":"` + token + `"}}`
	s := runMG(t, "tenant-1", &stubARM{bodies: map[string]string{"managementGroups": body}})
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
