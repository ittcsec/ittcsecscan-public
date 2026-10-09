package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// twoSources is a sources.list page: the built-in Security Health Analytics source and
// a third-party integration.
const twoSources = `{"sources":[
	{"name":"projects/proj/sources/111","displayName":"Security Health Analytics","description":"Google built-in posture scanner"},
	{"name":"projects/proj/sources/222","displayName":"Acme Scanner","description":"third-party integration"}
]}`

func sccStub() *stubGCP {
	return &stubGCP{bodies: map[string]string{"/sources": twoSources}}
}

func runSCC(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newSCCCollector(project, api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func sccSourceNode(s collect.Scan, name string) (collect.Node, bool) {
	id := "//securitycenter.googleapis.com/" + name
	for _, n := range s.Nodes {
		if n.Type == model.NodeControl && n.NativeID == id {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestSCCMapsSources proves each registered source becomes a control node keyed by its
// full resource name with its display name and description as facts, no verdict.
func TestSCCMapsSources(t *testing.T) {
	s := runSCC(t, "proj", sccStub())

	sha, ok := sccSourceNode(s, "projects/proj/sources/111")
	if !ok {
		t.Fatal("Security Health Analytics source not keyed by its full resource name")
	}
	if sha.Attributes["display_name"] != "Security Health Analytics" {
		t.Errorf("display_name = %q", sha.Attributes["display_name"])
	}
	if sha.Name != "Security Health Analytics" {
		t.Errorf("node name = %q, want the display name", sha.Name)
	}
	if _, ok := sccSourceNode(s, "projects/proj/sources/222"); !ok {
		t.Error("third-party source not emitted")
	}
	for _, forbidden := range []string{"enabled", "compliant", "coverage_ok"} {
		if _, bad := sha.Attributes[forbidden]; bad {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "scc.sources"); c.Status != collect.Complete || c.Collected != 2 {
		t.Errorf("scc.sources = %+v, want complete/2", c)
	}
}

// TestSCCDeniedIsGap proves a denied read (Security Command Center not activated or the
// permission missing) is a Denied gap, never a pass, and emits no node.
func TestSCCDeniedIsGap(t *testing.T) {
	api := &stubGCP{failSub: "/sources", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}}
	var s collect.Scan
	if err := newSCCCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied read must not fail the run: %v", err)
	}
	if statusOf(s, "scc.sources") != collect.Denied {
		t.Errorf("scc.sources = %s, want denied", statusOf(s, "scc.sources"))
	}
	if n := nodesByType(s)[model.NodeControl]; n != 0 {
		t.Errorf("control nodes = %d, want 0", n)
	}
}

// TestSCCServiceDisabledIsUnsupported proves a disabled Security Command Center API is
// Unsupported, not a denial and not a pass.
func TestSCCServiceDisabledIsUnsupported(t *testing.T) {
	api := &stubGCP{failSub: "/sources", failWith: &gcpError{status: 403, reason: "SERVICE_DISABLED", body: "Security Command Center API is not enabled"}}
	var s collect.Scan
	if err := newSCCCollector("proj", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if statusOf(s, "scc.sources") != collect.Unsupported {
		t.Errorf("scc.sources = %s, want unsupported", statusOf(s, "scc.sources"))
	}
}

// TestSCCEmptyIsComplete proves a project with no sources is an honest Complete/0.
func TestSCCEmptyIsComplete(t *testing.T) {
	s := runSCC(t, "proj", &stubGCP{bodies: map[string]string{"/sources": `{}`}})
	if c := completenessOf(s, "scc.sources"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("scc.sources = %+v, want complete/0", c)
	}
}

// TestSCCNoProjectIsUnsupported proves an empty project id is an Unsupported gap.
func TestSCCNoProjectIsUnsupported(t *testing.T) {
	s := runSCC(t, "", sccStub())
	if c := completenessOf(s, "scc.sources"); c.Status != collect.Unsupported {
		t.Errorf("scc.sources = %+v, want unsupported", c)
	}
}

// TestSCCPaginates proves nextPageToken is followed.
func TestSCCPaginates(t *testing.T) {
	api := &stubGCP{bodies: map[string]string{
		"/sources": `{"sources":[{"name":"projects/proj/sources/a"}],"nextPageToken":"np2"}`,
		"np2":      `{"sources":[{"name":"projects/proj/sources/b"}]}`,
	}}
	s := runSCC(t, "proj", api)
	if n := nodesByType(s)[model.NodeControl]; n != 2 {
		t.Errorf("sources across pages = %d, want 2", n)
	}
}

// TestSCCEvidenceRedactsToken proves the evidence body is scrubbed.
func TestSCCEvidenceRedactsToken(t *testing.T) {
	token := "ya29." + strings.Repeat("z", 60)
	api := &stubGCP{bodies: map[string]string{"/sources": `{"sources":[{"name":"projects/proj/sources/x","displayName":"` + token + `"}]}`}}
	s := runSCC(t, "proj", api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
