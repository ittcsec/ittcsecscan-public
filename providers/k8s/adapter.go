// Package k8s is the Kubernetes provider: a read-only credential adapter and scan
// source that enter through the same auth, collector, evidence, and completeness
// contracts as the cloud and source-control providers (ADR-0031). It authenticates
// with the in-cluster service account (the projected token and CA the API server
// mounts into every pod) and reads the cluster's identity and RBAC graph over the
// Kubernetes REST API with plain HTTPS and JSON, no client-go dependency, the same
// dependency-free shape as the GCP, Azure, GitHub, and GitLab collectors.
//
// Only in-cluster authentication is supported: the scanner runs as a pod with a
// read-only service account. Parsing an external kubeconfig file (which would need a
// YAML dependency) is a deliberately deferred follow-up (K8S-1), the same lean,
// platform-idiomatic choice the project made for every prior provider.
package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// The in-cluster service account credential locations the API server mounts into
// every pod (doc-verified against the Kubernetes access-from-pod reference).
const (
	//nolint:gosec // G101: this is the well-known mounted file PATH the API server
	// places the token at, not a hardcoded credential.
	tokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	namespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// identityProbePath is a low-privilege authenticated read used to establish that the
// service account credential works; /version is served by every API server.
const identityProbePath = "/version"

// apiStatusError carries a non-2xx status from the identity probe so classify can map
// it to an auth.Kind. Its message names no token.
type apiStatusError struct{ status int }

func (e *apiStatusError) Error() string {
	return fmt.Sprintf("kubernetes: identity probe returned HTTP %d", e.status)
}

// clusterConfig is the resolved in-cluster connection: the API server base URL, the
// bearer token, the trusted CA pool, and the service account's own namespace.
type clusterConfig struct {
	baseURL   string
	token     string
	caPool    *x509.CertPool
	namespace string
}

// Adapter implements auth.Resolver for Kubernetes.
type Adapter struct {
	// loadConfig resolves the in-cluster connection. Overridable in tests. The default
	// reads the mounted service account files and the API server env vars; the product
	// never stores the token.
	loadConfig func() (clusterConfig, error)
	// introspect confirms the credential works by calling the probe. Overridable in
	// tests; it must never surface the raw token in its error.
	introspect func(ctx context.Context, cfg clusterConfig) error
}

// New returns a Kubernetes adapter that authenticates with the in-cluster service
// account, reading the API server host and port from the given environment lookup and
// the token and CA from the mounted credential files. The lookup is injected because
// only the process entrypoint touches process state directly; the product never stores
// the token. It performs no I/O; the credential is resolved lazily on each Resolve.
func New(lookupEnv config.LookupEnv) *Adapter {
	return &Adapter{
		loadConfig: func() (clusterConfig, error) { return inClusterConfig(lookupEnv, os.ReadFile) },
		introspect: probe,
	}
}

// inClusterConfig assembles the connection from the API server env vars and the mounted
// service account files. readFile is injected so tests do not touch the filesystem.
func inClusterConfig(lookupEnv config.LookupEnv, readFile func(string) ([]byte, error)) (clusterConfig, error) {
	host, _ := lookupEnv("KUBERNETES_SERVICE_HOST")
	port, ok := lookupEnv("KUBERNETES_SERVICE_PORT_HTTPS")
	if !ok || strings.TrimSpace(port) == "" {
		port, _ = lookupEnv("KUBERNETES_SERVICE_PORT")
	}
	host, port = strings.TrimSpace(host), strings.TrimSpace(port)
	if host == "" || port == "" {
		return clusterConfig{}, errors.New("not running in a cluster: KUBERNETES_SERVICE_HOST/PORT not set")
	}
	tokenBytes, err := readFile(tokenPath)
	if err != nil {
		return clusterConfig{}, fmt.Errorf("reading service account token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return clusterConfig{}, errors.New("service account token file is empty")
	}
	caBytes, err := readFile(caPath)
	if err != nil {
		return clusterConfig{}, fmt.Errorf("reading cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return clusterConfig{}, errors.New("cluster CA file held no valid certificate")
	}
	ns := ""
	if nsBytes, err := readFile(namespacePath); err == nil {
		ns = strings.TrimSpace(string(nsBytes))
	}
	return clusterConfig{
		baseURL:   fmt.Sprintf("https://%s:%s", host, port),
		token:     token,
		caPool:    pool,
		namespace: ns,
	}, nil
}

// Resolve implements auth.Resolver. It establishes the caller's identity with the
// read-only probe, which performs no write, and returns a non-secret Identity naming
// the cluster and the service account's namespace. Every failure is routed through
// auth.Fail, so no token escapes in an error.
func (a *Adapter) Resolve(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, error) {
	id, _, err := a.resolveConfig(ctx, p, prof)
	return id, err
}

// resolveConfig resolves the connection once and confirms it, returning both the
// identity and the config, so the reported identity and the collectors' client cannot
// diverge (ADR-0018 §3). Every failure is routed through auth.Fail.
func (a *Adapter) resolveConfig(ctx context.Context, p model.Provider, prof auth.Profile) (auth.Identity, clusterConfig, error) {
	if p != model.Kubernetes {
		return auth.Identity{}, clusterConfig{}, auth.Fail(p, prof, auth.KindUnknown,
			errors.New("kubernetes adapter asked to resolve a non-kubernetes provider"))
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return auth.Identity{}, clusterConfig{}, auth.Fail(p, prof, auth.KindUnknown, err)
	}
	if err := a.introspect(ctx, cfg); err != nil {
		return auth.Identity{}, clusterConfig{}, auth.Fail(p, prof, classify(err), err)
	}
	principal := "in-cluster service account"
	if cfg.namespace != "" {
		principal = "system:serviceaccount:" + cfg.namespace
	}
	return auth.Identity{Provider: model.Kubernetes, Account: cfg.baseURL, Principal: principal}, cfg, nil
}

// probe issues the read-only identity probe with the resolved credential. The token is
// sent as a bearer credential and never logged or returned.
func probe(ctx context.Context, cfg clusterConfig) error {
	client := httpClientFor(cfg.caPool)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.baseURL+identityProbePath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return &apiStatusError{status: resp.StatusCode}
	}
	return nil
}

// httpClientFor builds an HTTPS client that trusts the cluster CA. It is bounded by a
// dial timeout and requires TLS 1.2 or better.
func httpClientFor(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// classify maps an identity-probe failure to an auth.Kind: 401 is an expired or invalid
// token, 403 is denied, anything else is unknown.
func classify(err error) auth.Kind {
	var se *apiStatusError
	if errors.As(err, &se) {
		switch se.status {
		case http.StatusUnauthorized:
			return auth.KindExpired
		case http.StatusForbidden:
			return auth.KindDenied
		}
	}
	return auth.KindUnknown
}
