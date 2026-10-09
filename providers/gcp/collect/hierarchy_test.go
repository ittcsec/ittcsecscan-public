package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const (
	hierProject = `{"name":"projects/12345","projectId":"proj","state":"ACTIVE","displayName":"Test Project","parent":"folders/f123"}`
	hierFolder  = `{"name":"folders/f123","parent":"organizations/o456","displayName":"Engineering","state":"ACTIVE"}`
	hierOrg     = `{"name":"organizations/o456","displayName":"example.com","directoryCustomerId":"C0abcdef","state":"ACTIVE"}`
)

func hierStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{
		"/projects/":      hierProject,
		"/folders/":       hierFolder,
		"/organizations/": hierOrg,
	}}
}

func runHierarchy(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newHierarchyCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func nodeNamed(s collect.Scan, tp model.NodeType, native string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == tp && n.NativeID == native {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestHierarchyWalksToOrg proves the parent walk emits the project (keyed by project
// id so it merges with the identity node), each folder, and the organization, each
// carrying its parent as a forward-key id fact, with no synthesized containment edge.
func TestHierarchyWalksToOrg(t *testing.T) {
	s := runHierarchy(t, "proj", hierStub())

	proj, ok := nodeNamed(s, model.NodeProject, "proj")
	if !ok {
		t.Fatal("project not keyed by its project id")
	}
	for k, want := range map[string]string{
		"hierarchy_type": "project", "state": "ACTIVE", "display_name": "Test Project",
		"parent_id": "//cloudresourcemanager.googleapis.com/folders/f123",
	} {
		if proj.Attributes[k] != want {
			t.Errorf("project %s = %q, want %q", k, proj.Attributes[k], want)
		}
	}

	folder, ok := nodeNamed(s, model.NodeOrganization, "//cloudresourcemanager.googleapis.com/folders/f123")
	if !ok {
		t.Fatal("folder not keyed by its canonical resource name")
	}
	for k, want := range map[string]string{
		"hierarchy_type": "folder", "display_name": "Engineering",
		"parent_id": "//cloudresourcemanager.googleapis.com/organizations/o456",
	} {
		if folder.Attributes[k] != want {
			t.Errorf("folder %s = %q, want %q", k, folder.Attributes[k], want)
		}
	}

	org, ok := nodeNamed(s, model.NodeOrganization, "//cloudresourcemanager.googleapis.com/organizations/o456")
	if !ok {
		t.Fatal("organization not keyed by its canonical resource name")
	}
	if org.Attributes["hierarchy_type"] != "organization" || org.Attributes["directory_customer_id"] != "C0abcdef" {
		t.Errorf("org attrs = %+v", org.Attributes)
	}
	if _, has := org.Attributes["parent_id"]; has {
		t.Errorf("organization must have no parent_id, got %q", org.Attributes["parent_id"])
	}
	for _, forbidden := range []string{"compliant", "root"} {
		if _, bad := org.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "resourcemanager.hierarchy"); c.Status != collect.Complete {
		t.Errorf("resourcemanager.hierarchy = %+v, want complete", c)
	}
}

// TestHierarchyStandaloneProject proves a project with no parent is an explicit
// standalone fact (just the project node), Complete.
func TestHierarchyStandaloneProject(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{"/projects/": `{"projectId":"proj","state":"ACTIVE"}`}}
	s := runHierarchy(t, "proj", api)
	proj, ok := nodeNamed(s, model.NodeProject, "proj")
	if !ok {
		t.Fatal("project not emitted")
	}
	if _, has := proj.Attributes["parent_id"]; has {
		t.Errorf("standalone project must have no parent_id, got %q", proj.Attributes["parent_id"])
	}
	if nodesByType(s)[model.NodeOrganization] != 0 {
		t.Errorf("standalone project must have no ancestor nodes")
	}
	if c := completenessOf(s, "resourcemanager.hierarchy"); c.Status != collect.Complete {
		t.Errorf("resourcemanager.hierarchy = %+v, want complete", c)
	}
}

// TestHierarchyProjectDeniedIsGap proves a denied project read is a Denied gap that
// emits no node.
func TestHierarchyProjectDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "/projects/", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newHierarchyCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "resourcemanager.hierarchy") != collect.Denied {
		t.Errorf("resourcemanager.hierarchy = %s, want denied", statusOf(s, "resourcemanager.hierarchy"))
	}
	if len(s.Nodes) != 0 {
		t.Errorf("nodes = %d, want 0", len(s.Nodes))
	}
}

// TestHierarchyAncestorDeniedIsPartial proves that when the project reads but a folder
// read is denied, the project stands and the record is Partial (an honest incomplete
// chain), never Complete and never an inferred parent.
func TestHierarchyAncestorDeniedIsPartial(t *testing.T) {
	api := &stubGCP{
		bodies:   map[string]string{"/projects/": hierProject},
		failSub:  "/folders/",
		failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"},
	}
	s := runHierarchy(t, "proj", api)
	if _, ok := nodeNamed(s, model.NodeProject, "proj"); !ok {
		t.Error("project must still be emitted when an ancestor is denied")
	}
	if nodesByType(s)[model.NodeOrganization] != 0 {
		t.Error("a denied folder read must not emit a folder node")
	}
	if statusOf(s, "resourcemanager.hierarchy") != collect.Partial {
		t.Errorf("resourcemanager.hierarchy = %s, want partial", statusOf(s, "resourcemanager.hierarchy"))
	}
}

// TestHierarchyServiceDisabledIsUnsupported proves a disabled Resource Manager API is
// Unsupported.
func TestHierarchyServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "/projects/", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Cloud Resource Manager API is not enabled"}}
	var s collect.Scan
	if err := newHierarchyCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "resourcemanager.hierarchy") != collect.Unsupported {
		t.Errorf("resourcemanager.hierarchy = %s, want unsupported", statusOf(s, "resourcemanager.hierarchy"))
	}
}

// TestHierarchyNoProjectIsUnsupported proves an empty project id is an Unsupported gap.
func TestHierarchyNoProjectIsUnsupported(t *testing.T) {
	s := runHierarchy(t, "", hierStub())
	if c := completenessOf(s, "resourcemanager.hierarchy"); c.Status != collect.Unsupported {
		t.Errorf("resourcemanager.hierarchy = %+v, want unsupported", c)
	}
}

// TestHierarchyEvidenceRedactsToken proves the evidence body is scrubbed.
func TestHierarchyEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("z", 60)
	api := &stubGCP{bodies: map[string]string{"/projects/": `{"projectId":"proj","displayName":"` + token + `"}`}}
	s := runHierarchy(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
