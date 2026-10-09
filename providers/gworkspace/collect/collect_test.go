package collect

import (
	"context"
	"errors"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// stubAPI serves canned pages in call order; a page's err, if set, is returned instead of
// a body.
type stubAPI struct {
	pages []stubResp
	calls int
	urls  []string
}

type stubResp struct {
	body string
	err  error
}

func (s *stubAPI) get(_ context.Context, url string) ([]byte, error) {
	s.urls = append(s.urls, url)
	if s.calls >= len(s.pages) {
		return nil, errors.New("unexpected extra page")
	}
	r := s.pages[s.calls]
	s.calls++
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.body), nil
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

const customer = "my_customer"

// The users collector follows nextPageToken across pages and emits one identity per user.
func TestUsersAcrossPages(t *testing.T) {
	api := &stubAPI{pages: []stubResp{
		{body: `{"users":[{"id":"u1","primaryEmail":"a@acme.com","name":{"fullName":"A One"},"isAdmin":true}],"nextPageToken":"tok2"}`},
		{body: `{"users":[{"id":"u2","primaryEmail":"b@acme.com","suspended":true}]}`},
	}}
	c := newUsersCollector(customer, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.Nodes) != 2 {
		t.Fatalf("emitted %d nodes, want 2", len(sink.Nodes))
	}
	u1, _ := findNode(sink.Nodes, "gws:user:u1")
	if u1.Type != model.NodeIdentity || u1.Name != "a@acme.com" || u1.Attributes["is_admin"] != "true" {
		t.Errorf("u1 wrong: %+v", u1)
	}
	u2, _ := findNode(sink.Nodes, "gws:user:u2")
	if u2.Attributes["suspended"] != "true" {
		t.Errorf("u2 suspended attr wrong: %+v", u2.Attributes)
	}
	if len(sink.Completeness) != 1 || !sink.Completeness[0].Done() || sink.Completeness[0].Collected != 2 {
		t.Errorf("unexpected completeness: %+v", sink.Completeness)
	}
	// Second request carried the page token.
	if want := "pageToken=tok2"; !contains(api.urls[1], want) {
		t.Errorf("second url %q did not carry %q", api.urls[1], want)
	}
}

func TestUsersDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubResp{{err: &gwsError{status: 403, body: "forbidden"}}}}
	c := newUsersCollector(customer, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied, got %+v", sink.Completeness)
	}
}

func TestGroupsEmitsGroupsAndMemberships(t *testing.T) {
	api := &stubAPI{pages: []stubResp{
		{body: `{"groups":[{"id":"g1","email":"admins@acme.com","name":"Admins"}]}`},
		{body: `{"members":[{"id":"u1","type":"USER"},{"id":"g2","type":"GROUP"}]}`},
	}}
	c := newGroupsCollector(customer, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	g, ok := findNode(sink.Nodes, "gws:group:g1")
	if !ok || g.Type != model.NodeGroup || g.Name != "admins@acme.com" {
		t.Fatalf("group node wrong: %+v", g)
	}
	if l, ok := findLink(sink.Links, "gws:user:u1", "gws:group:g1"); !ok || l.Kind != model.EdgeMemberOf {
		t.Fatalf("expected member_of user -> group, got %+v", sink.Links)
	}
	// A nested group member joins as a group.
	if _, ok := findLink(sink.Links, "gws:group:g2", "gws:group:g1"); !ok {
		t.Error("expected member_of nested-group -> group")
	}
}

func TestGroupsListDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubResp{{err: &gwsError{status: 401, body: "unauthorized"}}}}
	c := newGroupsCollector(customer, api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("denied listing must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected Denied, got %+v", sink.Completeness)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A throttled read (429) is a represented Partial gap (provider-throttling gate).
func TestGWSUsersThrottleIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubResp{{err: &gwsError{status: 429, body: "rate limited"}}}}
	var sink collect.Scan
	if err := newUsersCollector(customer, api).Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a throttled read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness on 429, got %+v", sink.Completeness)
	}
}
