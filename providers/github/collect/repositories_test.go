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

func findNode(nodes []collect.Node, nativeID string) (collect.Node, bool) {
	for _, n := range nodes {
		if n.NativeID == nativeID {
			return n, true
		}
	}
	return collect.Node{}, false
}

// The collector follows the Link header across pages, emits one repository node per
// repo keyed by full_name with its metadata, and records Complete.
func TestRepositoriesCollectAcrossPages(t *testing.T) {
	api := &stubAPI{pages: []stubPage{
		{body: `[{"full_name":"acme/web","name":"web","private":false,"visibility":"public","default_branch":"main","owner":{"login":"acme","type":"Organization"}}]`, next: "https://api.github.com/user/repos?page=2"},
		{body: `[{"full_name":"acme/secrets","name":"secrets","private":true,"visibility":"private","archived":true,"default_branch":"trunk","owner":{"login":"acme","type":"Organization"}}]`, next: ""},
	}}
	c := newRepositoriesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(sink.Nodes) != 2 {
		t.Fatalf("emitted %d nodes, want 2", len(sink.Nodes))
	}
	web, ok := findNode(sink.Nodes, "acme/web")
	if !ok || web.Type != model.NodeRepository || web.Name != "web" {
		t.Fatalf("web node wrong: %+v", web)
	}
	if web.Attributes["visibility"] != "public" || web.Attributes["private"] != "false" || web.Attributes["owner_type"] != "Organization" {
		t.Errorf("web attributes wrong: %+v", web.Attributes)
	}
	sec, _ := findNode(sink.Nodes, "acme/secrets")
	if sec.Attributes["private"] != "true" || sec.Attributes["archived"] != "true" || sec.Attributes["default_branch"] != "trunk" {
		t.Errorf("secrets attributes wrong: %+v", sec.Attributes)
	}
	if len(sink.Completeness) != 1 || !sink.Completeness[0].Done() {
		t.Errorf("expected one Complete record, got %+v", sink.Completeness)
	}
	if sink.Completeness[0].Collected != 2 {
		t.Errorf("collected count = %d, want 2", sink.Completeness[0].Collected)
	}
	if len(sink.Envelopes) != 2 {
		t.Errorf("expected 2 evidence envelopes (one per page), got %d", len(sink.Envelopes))
	}
	if api.urls[1] != "https://api.github.com/user/repos?page=2" {
		t.Errorf("did not follow the Link next url, second url = %q", api.urls[1])
	}
}

// A denied read is a represented Denied gap, never an error or a silent empty.
func TestRepositoriesDeniedIsGap(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &githubError{status: 403, body: "forbidden"}}}}
	c := newRepositoriesCollector("acme", api)
	var sink collect.Scan
	if err := c.Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a denied read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Denied {
		t.Errorf("expected a Denied completeness, got %+v", sink.Completeness)
	}
	if len(sink.Nodes) != 0 {
		t.Error("denied read must emit no nodes")
	}
}

func TestNextLink(t *testing.T) {
	cases := map[string]string{
		`<https://api.github.com/user/repos?page=2>; rel="next", <https://api.github.com/user/repos?page=5>; rel="last"`: "https://api.github.com/user/repos?page=2",
		`<https://api.github.com/user/repos?page=5>; rel="last"`:                                                         "",
		``: "",
	}
	for header, want := range cases {
		if got := nextLink(header); got != want {
			t.Errorf("nextLink(%q) = %q, want %q", header, got, want)
		}
	}
}

// A throttled read (429) is a represented Partial gap, never a hard error or silent pass
// (provider-throttling gate, the design).
func TestRepositoriesThrottleIsPartial(t *testing.T) {
	api := &stubAPI{pages: []stubPage{{err: &githubError{status: 429, body: "rate limited"}}}}
	var sink collect.Scan
	if err := newRepositoriesCollector("acme", api).Collect(context.Background(), &sink); err != nil {
		t.Fatalf("a throttled read must not be a hard error: %v", err)
	}
	if len(sink.Completeness) != 1 || sink.Completeness[0].Status != collect.Partial {
		t.Errorf("expected a Partial completeness on 429, got %+v", sink.Completeness)
	}
}
