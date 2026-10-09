package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// selfSignedCAPEM generates a throwaway CA certificate in PEM form so inClusterConfig's
// CA parsing can be exercised without a real cluster CA on disk.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestInClusterConfigReadsFilesAndEnv(t *testing.T) {
	ca := selfSignedCAPEM(t)
	files := map[string][]byte{
		tokenPath:     []byte("  tok-abc\n"),
		caPath:        ca,
		namespacePath: []byte("prod\n"),
	}
	read := func(p string) ([]byte, error) {
		b, ok := files[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return b, nil
	}
	cfg, err := inClusterConfig(envOf(map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1", "KUBERNETES_SERVICE_PORT_HTTPS": "443"}), read)
	if err != nil {
		t.Fatalf("inClusterConfig: %v", err)
	}
	if cfg.baseURL != "https://10.0.0.1:443" {
		t.Errorf("baseURL = %q", cfg.baseURL)
	}
	if cfg.token != "tok-abc" {
		t.Errorf("token not trimmed: %q", cfg.token)
	}
	if cfg.namespace != "prod" {
		t.Errorf("namespace = %q", cfg.namespace)
	}
	if cfg.caPool == nil {
		t.Error("caPool is nil")
	}
}

func TestInClusterConfigFailsClosed(t *testing.T) {
	ca := selfSignedCAPEM(t)
	okFiles := map[string][]byte{tokenPath: []byte("tok"), caPath: ca, namespacePath: []byte("prod")}
	read := func(files map[string][]byte) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			b, ok := files[p]
			if !ok {
				return nil, errors.New("no such file")
			}
			return b, nil
		}
	}
	// No API server env: not in a cluster.
	if _, err := inClusterConfig(envOf(nil), read(okFiles)); err == nil {
		t.Error("missing KUBERNETES_SERVICE_HOST/PORT must fail closed")
	}
	// Missing token file.
	noToken := map[string][]byte{caPath: ca, namespacePath: []byte("prod")}
	if _, err := inClusterConfig(envOf(map[string]string{"KUBERNETES_SERVICE_HOST": "h", "KUBERNETES_SERVICE_PORT": "443"}), read(noToken)); err == nil {
		t.Error("missing token must fail closed")
	}
	// Invalid CA.
	badCA := map[string][]byte{tokenPath: []byte("tok"), caPath: []byte("not a cert"), namespacePath: []byte("prod")}
	if _, err := inClusterConfig(envOf(map[string]string{"KUBERNETES_SERVICE_HOST": "h", "KUBERNETES_SERVICE_PORT": "443"}), read(badCA)); err == nil {
		t.Error("an invalid CA must fail closed")
	}
}

func TestResolveReturnsIdentity(t *testing.T) {
	a := &Adapter{
		loadConfig: func() (clusterConfig, error) {
			return clusterConfig{baseURL: "https://k8s:443", token: "tok", namespace: "prod"}, nil
		},
		introspect: func(context.Context, clusterConfig) error { return nil },
	}
	id, err := a.Resolve(context.Background(), model.Kubernetes, auth.Discovery)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Provider != model.Kubernetes || id.Account != "https://k8s:443" || id.Principal != "system:serviceaccount:prod" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func TestResolveRejectsWrongProvider(t *testing.T) {
	a := &Adapter{
		loadConfig: func() (clusterConfig, error) { return clusterConfig{}, nil },
		introspect: func(context.Context, clusterConfig) error { return nil },
	}
	if _, err := a.Resolve(context.Background(), model.AWS, auth.Discovery); err == nil {
		t.Fatal("kubernetes adapter must reject a non-kubernetes provider")
	}
}

func TestResolveFailsClosedWithoutCluster(t *testing.T) {
	a := &Adapter{
		loadConfig: func() (clusterConfig, error) { return clusterConfig{}, errors.New("not in a cluster") },
		introspect: func(context.Context, clusterConfig) error { return nil },
	}
	if _, err := a.Resolve(context.Background(), model.Kubernetes, auth.Discovery); err == nil {
		t.Fatal("no in-cluster credential must fail closed")
	}
}

func TestClassifyStatuses(t *testing.T) {
	cases := map[int]auth.Kind{401: auth.KindExpired, 403: auth.KindDenied, 500: auth.KindUnknown}
	for status, want := range cases {
		if got := classify(&apiStatusError{status: status}); got != want {
			t.Errorf("classify(%d) = %v, want %v", status, got, want)
		}
	}
	if got := classify(errors.New("network")); got != auth.KindUnknown {
		t.Errorf("classify(non-status) = %v, want KindUnknown", got)
	}
}

// A service account token (a JWT) caught in an error is scrubbed by auth.Fail (redact
// recognizes the JWT shape). The token is assembled at runtime so no token-shaped literal
// is committed.
func TestResolveErrorScrubsToken(t *testing.T) {
	tok := "eyJ" + "hbGciOiJSUzI1NiJ9" + ".eyJ" + "zdWIiOiJzYSJ9" + ".c2ln"
	a := &Adapter{
		loadConfig: func() (clusterConfig, error) { return clusterConfig{baseURL: "https://k8s:443", token: tok}, nil },
		introspect: func(context.Context, clusterConfig) error { return errors.New("probe failed with " + tok) },
	}
	_, err := a.Resolve(context.Background(), model.Kubernetes, auth.Discovery)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), tok) {
		t.Errorf("error leaked the token: %q", err.Error())
	}
}
