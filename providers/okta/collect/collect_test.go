package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

type stubPage struct {
	body string
	next string
	err  error
}

type stubAPI struct {
	pages []stubPage
	calls int
	urls  []string
}

func (s *stubAPI) get(_ context.Context, url string) ([]byte, string, error) {
	s.urls = append(s.urls, url)
	if s.calls >= len(s.pages) {
		return nil, "", errors.New("unexpected extra page")
	}
	p := s.pages[s.calls]
	s.calls++
	return []byte(p.body), p.next, p.err
}

func findNode(nodes []collect.Node, id string) (collect.Node, bool) {
	for _, n := range nodes {
		if n.NativeID == id {
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

const org = "https://acme.okta.com"

func TestUsersEmitsIdentityNodes(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":"u1","status":"ACTIVE","profile":{"login":"a@acme.com","email":"a@acme.com","firstName":"A","lastName":"One"}}]`, next: ""},
	}}
	c := newUsersCollector(org, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	n, ok := findNode(sink.Nodes, "okta:user:u1")
	if !ok || n.Type != model.NodeIdentity || n.Name != "a@acme.com" {
		t.Fatalf("user node wrong: %+v", n)
	}
	if n.Attributes["status"] != "ACTIVE" || n.Attributes["email"] != "a@acme.com" {
		t.Errorf("user attributes wrong: %+v", n.Attributes)
	}
	if len(sink.Completeness) != 1 || !sink.Completeness[0].Done() {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

func TestUsersDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &oktaError{status: 403, body: "forbidden"}}}}
	c := newUsersCollector(org, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 {
		t.Error("denied read must emit no nodes")
	}
}

func TestGroupsEmitsGroupsAndMemberships(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"id":"g1","type":"OKTA_GROUP","profile":{"name":"Admins","description":"admins"}}]`, next: ""},
		{body: `[{"id":"u1"},{"id":"u2"}]`, next: ""},
	}}
	c := newGroupsCollector(org, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	g, ok := findNode(sink.Nodes, "okta:group:g1")
	if !ok || g.Type != model.NodeGroup || g.Name != "Admins" {
		t.Fatalf("group node wrong: %+v", g)
	}
	if l, ok := findLink(sink.Links, "okta:user:u1", "okta:group:g1"); !ok || l.Kind != model.EdgeMemberOf {
		t.Fatalf("expected member_of edge user -> group, got %+v", sink.Links)
	}
	if _, ok := findLink(sink.Links, "okta:user:u2", "okta:group:g1"); !ok {
		t.Error("second member edge missing")
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Complete {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
}

func TestGroupsListDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &oktaError{status: 401, body: "unauthorized"}}}}
	c := newGroupsCollector(org, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied listing must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied, got %+v", sink.Completeness)
	}
}

func TestNextLink(t *testing.T) {
	cases := map[string]string{
		`<https://acme.okta.com/api/v1/users?after=abc>; rel="next"`: "https://acme.okta.com/api/v1/users?after=abc",
		`<https://acme.okta.com/api/v1/users?after=abc>; rel="self"`: "",
		``: "",
	}
	for header, want := range cases {
		if got := nextLink(header); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", header, got, want)
		}
	}
}

// A throttled read (429) is a represented Partial gap (provider-throttling gate).
func TestOktaUsersThrottleIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &oktaError{status: 429, body: "rate limited"}}}}
	var sink collect.Scan
	if err := newUsersCollector(org, api).Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a throttled read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness on 429, got %+v", sink.Completeness)
	}
}
