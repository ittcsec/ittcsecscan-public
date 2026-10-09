package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the GitHub read-only collectors for one scan, each with a client
// that authenticates with the resolved token. It is the single place the GitHub
// collector set is enumerated, so adding a collector (workflows as pipelines, build
// artifacts, the deploy-target join to the cloud workload graph) is one line here and
// the scan command picks it up unchanged. account is the authenticated login.
func Collectors(account, token string, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewRepositoriesCollector(account, token, budget),
		NewWorkflowsCollector(account, token, budget),
		NewArtifactsCollector(account, token, budget),
	}
}
