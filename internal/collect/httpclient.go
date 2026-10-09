package collect

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// DialTimeout and TLSHandshakeTimeout bound connection establishment for the
	// plain-HTTP provider clients (GCP and Azure). An unreachable endpoint (an
	// opt-in region not enabled, or one unreachable from the run environment) is
	// then rejected in seconds rather than hanging, which matters most when a
	// resource collector fans out across many regions. They match the values the
	// AWS SDK clients use (providers/aws), so this class of protection is one mental
	// model across the codebase. The response body read is deliberately left
	// unbounded, so a legitimately large paginated response from a working endpoint
	// is never cut off.
	DialTimeout         = 5 * time.Second
	TLSHandshakeTimeout = 5 * time.Second
)

// DialEvent is one outbound connection attempt, as seen at the dial layer: the
// destination the client asked to reach and the outcome. No credential, request
// header, or body is visible here; only the network and the host:port address.
type DialEvent struct {
	// Network is the dial network ("tcp", "tcp4", and so on).
	Network string
	// Address is the destination host:port the HTTP client asked the dialer to reach.
	Address string
	// At is when the attempt started.
	At time.Time
	// Err is the raw connection error, or empty on success. It is a transport error
	// (refused, timed out, no such host), never a credential; the writer redacts it.
	Err string
}

// dialObserver is the process-wide hook called once per outbound dial attempt. It is
// nil by default (no observation, no cost beyond a nil check), and set by the
// --offline-audit path at scan start, before any provider call. Guarded by a mutex so
// it can be set and read from different goroutines safely.
var (
	dialObsMu    sync.RWMutex
	dialObserver func(DialEvent)
)

// SetDialObserver installs f as the observer called for every outbound connection
// attempt the shared HTTP clients make (nil disables). It is the one switch the
// zero-egress audit mode flips; it is process-wide because the shared clients are
// package-level singletons constructed before flags are parsed, so observation is
// decided per dial, not per client. Set it before the scan runs and clear it after.
func SetDialObserver(f func(DialEvent)) {
	dialObsMu.Lock()
	dialObserver = f
	dialObsMu.Unlock()
}

// notifyDial reports one attempt to the installed observer, if any. It never panics on
// a nil observer and holds the lock only to read the function pointer.
func notifyDial(network, addr string, at time.Time, err error) {
	dialObsMu.RLock()
	f := dialObserver
	dialObsMu.RUnlock()
	if f == nil {
		return
	}
	e := DialEvent{Network: network, Address: addr, At: at}
	if err != nil {
		e.Err = err.Error()
	}
	f(e)
}

// auditedDialContext wraps a dialer so every attempt it makes is reported to the
// observer (when one is installed), without changing the dial's result. The address is
// the destination host:port; the observer sees nothing else about the request.
func auditedDialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		conn, err := d.DialContext(ctx, network, addr)
		notifyDial(network, addr, start, err)
		return conn, err
	}
}

// AuditedDialContext returns a DialContext backed by a dialer with the given dial
// timeout, reporting every attempt to the installed observer. The AWS SDK client uses
// it (providers/aws), so AWS egress is audited by the same observer as the plain-HTTP
// providers, and the audit covers the whole scan from one switch.
func AuditedDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return auditedDialContext(&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second})
}

// BoundedHTTPClient returns an HTTP client that fails fast on an unreachable
// endpoint: a bounded dial and TLS-handshake timeout, with no overall client
// timeout (the body read stays unbounded). It clones the default transport, so
// its proxy, keep-alive, and connection-pool behaviour is preserved and only the
// connection-establishment timeouts are tightened. It is the one definition the
// plain-HTTP provider clients share, so the timeout policy cannot drift between
// providers. Its dialer reports every attempt to the installed dial observer, so the
// zero-egress audit mode sees every connection these clients make.
func BoundedHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = auditedDialContext(&net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second})
	tr.TLSHandshakeTimeout = TLSHandshakeTimeout
	return &http.Client{Transport: tr}
}
