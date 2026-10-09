package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// denyAssignment is the subset of an Azure deny-assignment we read: the principals
// it denies and the actions it denies them. A deny-assignment is an explicit deny
// that overrides role-assignment allows (Azure RBAC), so it feeds Step 4's
// explicit-deny path (ADR-0022 EP-6).
type denyAssignment struct {
	Properties struct {
		Principals []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"principals"`
		Permissions []azurePermission `json:"permissions"`
	} `json:"properties"`
}

// denyAssignments reads a subscription's deny-assignments and stamps a
// deny_privilege_level fact on each denied principal (the privilege the denied
// actions represent, reusing the same action classification as role definitions).
// The read was verified against the Azure REST reference (Microsoft.Authorization/
// denyAssignments, api-version 2022-04-01): a read-only GET, paginated by nextLink.
func (c *RBACCollector) denyAssignments(ctx context.Context, sink collect.Sink, subID string, scope collect.Scope) {
	levels := map[string]string{}
	types := map[string]string{}
	_ = c.pageThrough(ctx, sink, "rbac.denyAssignments", scope, authorizationAPIVersion,
		fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/denyAssignments?api-version=%s", armBaseURL, subID, authorizationAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []denyAssignment
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			for _, da := range page {
				level, _ := classifyAzureRole(da.Properties.Permissions)
				if level == "" {
					continue
				}
				for _, p := range da.Properties.Principals {
					if p.ID == "" {
						continue
					}
					if higherAzureDeny(levels[p.ID], level) == level {
						levels[p.ID] = level
					}
					types[p.ID] = p.Type
				}
			}
			return len(page), nil
		})
	for _, id := range sortedDenyKeys(levels) {
		node, ok := rbacPrincipalNode(id, types[id])
		if !ok {
			continue
		}
		node.Attributes = attrs("deny_privilege_level", levels[id])
		_ = sink.Node(node)
	}
}

func higherAzureDeny(a, b string) string {
	rank := map[string]int{"": 0, "privileged": 1, "admin": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func sortedDenyKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
