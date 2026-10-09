//go:build live

// This file builds only under the "live" tag, so CI (which never holds cloud
// credentials) does not compile or run it. It is the maintainer-run live
// verification required by ADR-0016 §3.
//
// Run it against the disposable Azure test tenant with credentials in the
// environment (AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET) or via the
// Azure CLI (az login):
//
//	go test -tags live -run TestLive -v ./providers/azure/
//
// Set ITTCSECSCAN_LIVE_AZURE_TENANT to the expected tenant id to assert it; the
// tenant id is not committed to the repository.
package azure

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveResolveTenant resolves the real Azure identity through
// DefaultAzureCredential and the ARM Tenants - List call, and prints it. It
// proves the adapter authenticates end to end against the live test tenant.
func TestLiveResolveTenant(t *testing.T) {
	id, err := New().Resolve(context.Background(), model.Azure, auth.Discovery)
	if err != nil {
		t.Fatalf("live resolve failed: %v", err)
	}
	if id.Account == "" {
		t.Fatalf("live identity has no tenant: %+v", id)
	}
	if want := os.Getenv("ITTCSECSCAN_LIVE_AZURE_TENANT"); want != "" && id.Account != want {
		t.Fatalf("resolved tenant %s, want %s", id.Account, want)
	}
	// Principal is the tenant display name, not a specific principal (see the
	// adapter and auth.Identity docs).
	t.Logf("live Azure identity: tenant=%s tenant-name=%s", id.Account, id.Principal)
}
