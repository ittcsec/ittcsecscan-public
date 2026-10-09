package update

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeBundle writes a fixture's metadata and target content to an offline bundle
// directory laid out the way DirFetcher and TargetPath expect.
func writeBundle(t *testing.T, dir string, f fixture) {
	t.Helper()
	write := func(name string, data []byte) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("root.json", f.rootRaw)
	write("timestamp.json", f.repo.files["timestamp.json"])
	write("snapshot.json", f.repo.files["snapshot.json"])
	write("targets.json", f.repo.files["targets.json"])
	write(TargetPath(f.targetName), f.targetData)
}

// The offline path end to end: verify the chain from a signed bundle with no network,
// fetch and verify the target, and install it into a store.
func TestOfflineBundleEndToEnd(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	bundle := t.TempDir()
	writeBundle(t, bundle, f)

	fetcher := NewDirFetcher(bundle)
	c, err := NewClient(f.rootRaw, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	tgts, err := c.VerifyChain(fetcher)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	tgt, data, err := c.FetchAndVerifyTarget(fetcher, tgts, f.targetName)
	if err != nil {
		t.Fatalf("FetchAndVerifyTarget: %v", err)
	}
	if !bytes.Equal(data, f.targetData) {
		t.Fatal("fetched target content does not match")
	}

	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Install(tgt.Custom.Component, tgt.Custom.Version, data); err != nil {
		t.Fatal(err)
	}
	if got := s.mustInstalled(t)[tgt.Custom.Component].Version; got != "1.0.0" {
		t.Errorf("installed version %q, want 1.0.0", got)
	}
}

// A tampered target file in the bundle is refused (compromised-mirror case).
func TestOfflineBundleTamperedTargetRejected(t *testing.T) {
	f := buildFixture(t, 1, testNow.Add(24*time.Hour))
	bundle := t.TempDir()
	writeBundle(t, bundle, f)
	// Corrupt the target content on disk.
	if err := os.WriteFile(filepath.Join(bundle, filepath.FromSlash(TargetPath(f.targetName))), []byte("evil payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher := NewDirFetcher(bundle)
	c, _ := NewClient(f.rootRaw, fixedNow)
	tgts, err := c.VerifyChain(fetcher)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.FetchAndVerifyTarget(fetcher, tgts, f.targetName); !errors.Is(err, ErrTarget) {
		t.Fatalf("want ErrTarget for tampered bundle target, got %v", err)
	}
}

func TestDirFetcherRefusesTraversal(t *testing.T) {
	d := NewDirFetcher(t.TempDir())
	if _, err := d.Fetch("../secret"); err == nil {
		t.Error("DirFetcher must refuse a path that escapes the bundle")
	}
}

// The no-inventory / no-credentials guarantee: an update fetch is a bare GET with a
// minimal User-Agent, no request body, and no authorization or cookies.
func TestHTTPFetcherTransmitsNoInventoryOrCredentials(t *testing.T) {
	var gotMethod, gotAuth, gotCookie, gotUA string
	var gotBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotUA = r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("metadata"))
	}))
	defer ts.Close()

	h, err := NewHTTPFetcher(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.client = ts.Client() // trust the test server's cert (same package)

	body, err := h.Fetch("timestamp.json")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(body, []byte("metadata")) {
		t.Errorf("unexpected body: %q", body)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if len(gotBody) != 0 {
		t.Errorf("request carried a body (%d bytes); an update check must send none", len(gotBody))
	}
	if gotAuth != "" || gotCookie != "" {
		t.Errorf("request carried credentials: auth=%q cookie=%q", gotAuth, gotCookie)
	}
	if gotUA == "" {
		t.Error("no User-Agent set")
	}
}

func TestHTTPFetcherRequiresHTTPS(t *testing.T) {
	if _, err := NewHTTPFetcher("http://example.com/repo"); err == nil {
		t.Error("NewHTTPFetcher must reject a non-https URL")
	}
}

func (s *Store) mustInstalled(t *testing.T) map[string]InstalledInfo {
	t.Helper()
	m, err := s.Installed()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
