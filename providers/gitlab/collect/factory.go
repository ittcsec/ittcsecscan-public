package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the GitLab read-only collectors for one scan, each with a client
// that authenticates with the resolved token. It is the single place the GitLab
// collector set is enumerated, so adding a collector (pipelines from the project CI
// config, job artifacts, the OIDC federation join to the cloud workload graph) is one
// line here and the scan command picks it up unchanged. account is the authenticated
// username.
func Collectors(account, token string, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewProjectsCollector(account, token, budget),
		NewPipelinesCollector(account, token, budget),
		NewArtifactsCollector(account, token, budget),
	}
}
