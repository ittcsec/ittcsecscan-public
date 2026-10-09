package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the Kubernetes read-only collectors for one scan, each sharing the
// resolved API client. It is the single place the Kubernetes collector set is enumerated,
// so adding a collector (workloads and their service-account bindings, network policies)
// is one line here and the scan command picks it up unchanged. account is the cluster's
// API server URL.
func Collectors(account string, api API, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewNamespacesCollector(account, api, budget),
		NewServiceAccountsCollector(account, api, budget),
		NewRBACCollector(account, api, budget),
	}
}
