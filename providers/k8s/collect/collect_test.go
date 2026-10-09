package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubAPI serves canned pages keyed by the path prefix (before "?"), so a collector's
// pagination and multi-resource reads can be driven without a network or token. A page's
// err, if set, is returned instead of a body.
type stubAPI struct {
	pages map[string]stubResp
	calls []string
}

type stubResp struct {
	body string
	err  error
}

func (s *stubAPI) Get(_ context.Context, url string) ([]byte, error) {
	s.calls = append(s.calls, url)
	prefix := url
	if i := indexByte(url, '?'); i >= 0 {
		prefix = url[:i]
	}
	r, ok := s.pages[prefix]
	if !ok {
		return nil, errors.New("unexpected path " + prefix)
	}
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.body), nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func findNode(nodes []collect.Node, nativeID string) (collect.Node, bool) {
	for _, n := range nodes {
		if n.NativeID == nativeID {
			return n, true
		}
	}
	return collect.Node{}, false
}

func findLink(links []collect.Link, source, target string) (collect.Link, bool) {
	for _, l := range links {
		if l.SourceNativeID == source && l.TargetNativeID == target {
			return l, true
		}
	}
	return collect.Link{}, false
}

const cluster = "https://k8s.example:443"

// The namespaces collector emits the cluster node once and one namespace node per
// namespace with a contains edge from the cluster.
func TestNamespacesEmitsClusterAndContains(t *testing.T) {
	api := &stubAPI{pages: map[string]stubResp{
		"/api/v1/namespaces": {body: `{"items":[{"metadata":{"name":"default","uid":"u1"}},{"metadata":{"name":"kube-system","uid":"u2"}}],"metadata":{}}`},
	}}
	c := NewNamespacesCollector(cluster, api, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cl, ok := findNode(sink.Nodes, cluster)
	if !ok || cl.Type != model.NodeCluster {
		t.Fatalf("cluster node missing/wrong: %+v", cl)
	}
	ns, ok := findNode(sink.Nodes, "namespace:default")
	if !ok || ns.Type != model.NodeNamespace || ns.Name != "default" {
		t.Fatalf("namespace node wrong: %+v", ns)
	}
	if _, ok := findLink(sink.Links, cluster, "namespace:default"); !ok {
		t.Fatalf("expected contains edge cluster -> namespace, got %+v", sink.Links)
	}
	if len(sink.Completeness) != 1 || !sink.Completeness[0].Done() || sink.Completeness[0].Collected != 2 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

// A denied namespace listing is a represented Denied gap, but the cluster node is still
// emitted (the authenticated endpoint is real).
func TestNamespacesDeniedStillEmitsCluster(t *testing.T) {
	api := &stubAPI{pages: map[string]stubResp{
		"/api/v1/namespaces": {err: &k8sError{status: 403, body: "forbidden"}},
	}}
	c := NewNamespacesCollector(cluster, api, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied read must not be a hard error: %v", err)
	}
	if _, ok := findNode(sink.Nodes, cluster); !ok {
		t.Error("cluster node must be emitted even when namespaces are denied")
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied completeness, got %+v", sink.Completeness)
	}
}

// The service accounts collector emits each SA as an identity keyed by its canonical
// principal with a contains edge from its namespace.
func TestServiceAccountsEmitsIdentityAndContains(t *testing.T) {
	api := &stubAPI{pages: map[string]stubResp{
		"/api/v1/serviceaccounts": {body: `{"items":[{"metadata":{"name":"deployer","namespace":"prod","uid":"s1"}}],"metadata":{}}`},
	}}
	c := NewServiceAccountsCollector(cluster, api, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	const said = "system:serviceaccount:prod:deployer"
	n, ok := findNode(sink.Nodes, said)
	if !ok || n.Type != model.NodeIdentity || n.Attributes["kind"] != "ServiceAccount" {
		t.Fatalf("service account node wrong: %+v", n)
	}
	if _, ok := findLink(sink.Links, "namespace:prod", said); !ok {
		t.Fatalf("expected contains edge namespace -> serviceaccount, got %+v", sink.Links)
	}
}

// The RBAC collector emits role nodes and an assumes edge from a bound service account to
// the ClusterRole it is bound to, across all four RBAC resource types.
func TestRBACEmitsRolesAndAssumesEdges(t *testing.T) {
	api := &stubAPI{pages: map[string]stubResp{
		rbacGroup + "/clusterroles":        {body: `{"items":[{"metadata":{"name":"admin","uid":"r1"}}],"metadata":{}}`},
		rbacGroup + "/roles":               {body: `{"items":[{"metadata":{"name":"reader","namespace":"prod"}}],"metadata":{}}`},
		rbacGroup + "/clusterrolebindings": {body: `{"items":[{"metadata":{"name":"admins"},"roleRef":{"kind":"ClusterRole","name":"admin"},"subjects":[{"kind":"ServiceAccount","name":"deployer","namespace":"prod"}]}],"metadata":{}}`},
		rbacGroup + "/rolebindings":        {body: `{"items":[{"metadata":{"name":"readers","namespace":"prod"},"roleRef":{"kind":"Role","name":"reader"},"subjects":[{"kind":"Group","name":"team-a"}]}],"metadata":{}}`},
	}}
	c := NewRBACCollector(cluster, api, nil)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if n, ok := findNode(sink.Nodes, "clusterrole:admin"); !ok || n.Type != model.NodeRole || n.Attributes["kind"] != "ClusterRole" {
		t.Fatalf("clusterrole node wrong: %+v", n)
	}
	if n, ok := findNode(sink.Nodes, "role:prod:reader"); !ok || n.Type != model.NodeRole {
		t.Fatalf("role node wrong: %+v", n)
	}
	// ServiceAccount deployer assumes clusterrole admin.
	if l, ok := findLink(sink.Links, "system:serviceaccount:prod:deployer", "clusterrole:admin"); !ok || l.Kind != model.EdgeAssumes {
		t.Fatalf("expected assumes edge SA -> clusterrole, got %+v", sink.Links)
	}
	// Group team-a assumes role prod/reader, and the group node is emitted.
	if _, ok := findNode(sink.Nodes, "group:team-a"); !ok {
		t.Error("group subject node not emitted")
	}
	if l, ok := findLink(sink.Links, "group:team-a", "role:prod:reader"); !ok || l.Kind != model.EdgeAssumes {
		t.Fatalf("expected assumes edge group -> role, got %+v", sink.Links)
	}
	if len(sink.Completeness) != 4 {
		t.Errorf("expected 4 completeness records (one per RBAC resource), got %d", len(sink.Completeness))
	}
}

// A binding referencing a Role but carrying no namespace (a malformed ClusterRoleBinding
// pointing at a namespaced Role) yields no edge: the role cannot be located, never guessed.
func TestRBACRoleRefWithoutNamespaceYieldsNoEdge(t *testing.T) {
	if got := roleRefID(roleRef{Kind: "Role", Name: "reader"}, ""); got != "" {
		t.Errorf("roleRefID for a Role with no namespace = %q, want empty", got)
	}
	if got := roleRefID(roleRef{Kind: "ClusterRole", Name: "admin"}, ""); got != "clusterrole:admin" {
		t.Errorf("roleRefID(ClusterRole) = %q, want clusterrole:admin", got)
	}
}

// A throttled read (429) is a represented Partial gap (provider-throttling gate).
func TestNamespacesThrottleIsPartial(t *testing.T) {
	api := &stubAPI{pages: map[string]stubResp{
		"/api/v1/namespaces": {err: &k8sError{status: 429, body: "too many requests"}},
	}}
	var sink collect.Scan
	if err := NewNamespacesCollector(cluster, api, nil).Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a throttled read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness on 429, got %+v", sink.Completeness)
	}
}
