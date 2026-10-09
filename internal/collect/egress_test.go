package collect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// drainObserver collects DialEvents under a lock, for assertions.
type drainObserver struct {
	mu     sync.Mutex
	events []DialEvent
}

func (d *drainObserver) observe(e DialEvent) {
	d.mu.Lock()
	d.events = append(d.events, e)
	d.mu.Unlock()
}

func (d *drainObserver) all() []DialEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DialEvent(nil), d.events...)
}

// getWith issues a context-bound GET through c and closes the body.
func getWith(t *testing.T, c *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// TestDialObserverRecordsSuccessfulDial proves the shared client reports every outbound
// connection attempt it makes, with the destination address, to the installed observer.
// A mutation that drops the notifyDial call makes this fail: the core audit guarantee.
func TestDialObserverRecordsSuccessfulDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	var obs drainObserver
	SetDialObserver(obs.observe)
	defer SetDialObserver(nil)

	if err := getWith(t, BoundedHTTPClient(), srv.URL); err != nil {
		t.Fatalf("get: %v", err)
	}

	events := obs.all()
	if len(events) == 0 {
		t.Fatal("no dial recorded; the audit would miss this connection")
	}
	want := srv.Listener.Addr().String()
	var found bool
	for _, e := range events {
		if e.Address == want {
			found = true
			if e.Err != "" {
				t.Errorf("successful dial recorded an error: %q", e.Err)
			}
			if e.At.IsZero() {
				t.Error("dial event has no timestamp")
			}
		}
	}
	if !found {
		t.Errorf("recorded addresses %v do not include the server %q", events, want)
	}
}

// TestDialObserverRecordsFailedDial proves a failed connection attempt is still recorded,
// with its error, so the audit shows attempts that did not succeed.
func TestDialObserverRecordsFailedDial(t *testing.T) {
	// A closed port on loopback: the dial attempt is made and refused.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens now; the dial will be refused

	var obs drainObserver
	SetDialObserver(obs.observe)
	defer SetDialObserver(nil)

	dial := AuditedDialContext(1 * time.Second)
	if _, derr := dial(context.Background(), "tcp", addr); derr == nil {
		t.Skip("expected the dial to a closed port to fail; environment allowed it")
	}
	events := obs.all()
	if len(events) != 1 || events[0].Address != addr || events[0].Err == "" {
		t.Fatalf("failed dial not recorded with its error: %+v", events)
	}
}

// TestDialObserverOffIsSilent proves that with no observer installed nothing is recorded
// and dialing still works (zero overhead, zero behavior change when the mode is off).
func TestDialObserverOffIsSilent(t *testing.T) {
	SetDialObserver(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if err := getWith(t, BoundedHTTPClient(), srv.URL); err != nil {
		t.Fatalf("get with no observer: %v", err)
	}
}

// TestDialObserverConcurrent proves Set/notify are safe under concurrent dials, matching
// how the shared clients dial from many collector goroutines at once.
func TestDialObserverConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	var obs drainObserver
	SetDialObserver(obs.observe)
	defer SetDialObserver(nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Transport: &http.Transport{DialContext: AuditedDialContext(2 * time.Second)}}
			_ = getWith(t, c, srv.URL)
		}()
	}
	wg.Wait()
	if len(obs.all()) == 0 {
		t.Error("concurrent dials recorded nothing")
	}
}
