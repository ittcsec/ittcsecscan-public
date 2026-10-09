//go:build live

// Run against the disposable test accounts (ADR-0016 §3):
//
//	go test -tags live -run TestLive -v ./permissions/live/
//
// It needs credentials for the providers it checks (AWS via the environment or a
// profile, Azure via az login or AZURE_* env, GCP via Application Default
// Credentials). It performs only the zero-permission identity probe today.
package live

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/permissions"
	awsprovider "github.com/ittcsec/ittcsecscan/providers/aws"
	azureprovider "github.com/ittcsec/ittcsecscan/providers/azure"
	gcpprovider "github.com/ittcsec/ittcsecscan/providers/gcp"
	githubprovider "github.com/ittcsec/ittcsecscan/providers/github"
)

// TestLiveVerifyDiscoveryBaseline proves the discovery templates' current,
// provable baseline against the real test accounts: the zero-permission identity
// probe resolves for each provider, so the (empty) discovery template is
// sufficient today. It also walks each template's permissions to run the
// per-permission access-denied check; there are none until the collectors
// declare them, so the loop is the scaffold that later verification fills.
//
// This is the harness the ADR-0016 §3 gate refers to. Once a permission is
// proven here, the maintainer records the verification (date and method) in the
// template file; the schema and TestVerifiedTemplatesHaveEvidence keep that
// claim honest.
func TestLiveVerifyDiscoveryBaseline(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(model.AWS, awsprovider.New())
	reg.Register(model.Azure, azureprovider.New())
	reg.Register(model.GCP, gcpprovider.New())
	reg.Register(model.GitHub, githubprovider.New(os.LookupEnv))

	for _, p := range model.Providers {
		p := p
		t.Run(string(p), func(t *testing.T) {
			// Baseline sufficiency: the identity resolves with no permission.
			id, err := reg.Resolve(context.Background(), p, auth.Discovery)
			if err != nil {
				t.Fatalf("baseline identity did not resolve: %v", err)
			}
			t.Logf("identity resolved: account=%q principal=%q", id.Account, id.Principal)

			tpl, err := permissions.Load(p, permissions.Discovery)
			if err != nil {
				t.Fatalf("load discovery template: %v", err)
			}
			if len(tpl.Permissions) == 0 {
				t.Logf("discovery: 0 declared permissions; per-permission access-denied verification activates with the collectors")
				return
			}
			for _, e := range tpl.Permissions {
				// a later milestone: deny e.Permission and confirm the collector it
				// enables fails closed with an access-denied, never a silent
				// pass. Recording the result flips the entry to verified.
				t.Logf("discovery: %s is pending per-permission access-denied verification", e.Permission)
			}
		})
	}
}
