package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the Okta read-only collectors for one scan, each with a client that
// authenticates with the resolved API token. account is the org URL.
func Collectors(account, token string, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewUsersCollector(account, token, budget),
		NewGroupsCollector(account, token, budget),
	}
}
