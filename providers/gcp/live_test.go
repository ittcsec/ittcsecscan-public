//go:build live

// This file builds only under the "live" tag, so CI (which never holds cloud
// credentials) does not compile or run it. It is the maintainer-run live
// verification required by ADR-0016 §3.
//
// Run it against the disposable GCP test project with Application Default
// Credentials in the environment (gcloud auth application-default login, or a
// service-account key via GOOGLE_APPLICATION_CREDENTIALS):
//
//	go test -tags live -run TestLive -v ./providers/gcp/
//
// Set ITTCSECSCAN_LIVE_GCP_PRINCIPAL to the expected principal email to assert
// it; the value is not committed to the repository.
package gcp

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveResolvePrincipal resolves the real GCP identity through Application
// Default Credentials and token introspection, and prints it. It proves the
// adapter authenticates end to end against the live test project.
func TestLiveResolvePrincipal(t *testing.T) {
	id, err := New().Resolve(context.Background(), model.GCP, auth.Discovery)
	if err != nil {
		t.Fatalf("live resolve failed: %v", err)
	}
	if id.Principal == "" {
		t.Fatalf("live identity has no principal: %+v", id)
	}
	if want := os.Getenv("ITTCSECSCAN_LIVE_GCP_PRINCIPAL"); want != "" && id.Principal != want {
		t.Fatalf("resolved principal %s, want %s", id.Principal, want)
	}
	// Account (project) may be empty for a credential without a default project.
	t.Logf("live GCP identity: project=%q principal=%s", id.Account, id.Principal)
}
