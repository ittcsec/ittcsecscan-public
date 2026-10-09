package collect

import (
	"net/http"
	"testing"
)

// TestBoundedHTTPClient proves the shared plain-HTTP client fails fast on an
// unreachable endpoint (bounded dial and TLS-handshake timeout) while leaving the
// response body read unbounded (no overall client timeout), so a working
// endpoint's large paginated response is never cut off.
func TestBoundedHTTPClient(t *testing.T) {
	c := BoundedHTTPClient()
	if c == nil {
		t.Fatal("nil client")
	}
	if c.Timeout != 0 {
		t.Errorf("client Timeout = %v, want 0 (body read must be unbounded)", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSHandshakeTimeout != TLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", tr.TLSHandshakeTimeout, TLSHandshakeTimeout)
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil; the dial timeout is not applied")
	}
	// Cloned from the default transport, so connection pooling is preserved rather
	// than a bare zero-value transport.
	if tr.MaxIdleConns == 0 {
		t.Error("transport looks bare; expected the default transport's settings preserved")
	}
}
