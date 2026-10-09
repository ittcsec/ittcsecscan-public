package providers

import (
	"github.com/ittcsec/ittcsecscan/internal/config"
	"github.com/ittcsec/ittcsecscan/internal/scan"
	awsprovider "github.com/ittcsec/ittcsecscan/providers/aws"
	azureprovider "github.com/ittcsec/ittcsecscan/providers/azure"
	gcpprovider "github.com/ittcsec/ittcsecscan/providers/gcp"
	githubprovider "github.com/ittcsec/ittcsecscan/providers/github"
	gitlabprovider "github.com/ittcsec/ittcsecscan/providers/gitlab"
	gwsprovider "github.com/ittcsec/ittcsecscan/providers/gworkspace"
	k8sprovider "github.com/ittcsec/ittcsecscan/providers/k8s"
	mcpprovider "github.com/ittcsec/ittcsecscan/providers/mcp"
	oktaprovider "github.com/ittcsec/ittcsecscan/providers/okta"
)

// ScanSources returns the provider sources that are scannable today: the ones
// that have read-only collectors wired. It is deliberately not "every provider
// with a credential adapter": Azure and GCP authenticate (auth plan) but have no
// collectors yet, so listing them here would let a scan report a provider as
// fully covered while collecting nothing. A provider joins this list only when
// it has collectors to run, so coverage stays honest. They are returned in a
// stable order.
func ScanSources(lookupEnv config.LookupEnv) []scan.Source {
	return []scan.Source{
		awsprovider.NewSource(),
		azureprovider.NewSource(),
		gcpprovider.NewSource(),
		githubprovider.NewSource(lookupEnv),
		gitlabprovider.NewSource(lookupEnv),
		k8sprovider.NewSource(lookupEnv),
		oktaprovider.NewSource(lookupEnv),
		gwsprovider.NewSource(lookupEnv),
		mcpprovider.NewSource(lookupEnv),
	}
}
