package collect

import "github.com/ittcsec/ittcsecscan/internal/collect"

// Collectors builds the Google Workspace read-only collectors for one scan, each with a
// client that authenticates with the resolved bearer token. account is the customer alias.
func Collectors(account, token string, budget *collect.Budget) []collect.Collector {
	return []collect.Collector{
		NewUsersCollector(account, token, budget),
		NewGroupsCollector(account, token, budget),
	}
}
