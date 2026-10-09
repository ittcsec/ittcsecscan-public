package collect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const groupsCollectorID = "collector:okta.groups"

// GroupsCollector reads an Okta org's groups and their memberships: GET /api/v1/groups,
// then GET /api/v1/groups/{id}/users per group, both read-only Link-paginated calls
// verified against the Okta Groups API. It emits one group node per group and a member_of
// edge from each member user (keyed by the same Okta user id the users collector emits) to
// the group, so the identity-to-group graph joins in one scan.
type GroupsCollector struct {
	account string
	api     oktaAPI
	budget  *collect.Budget
}

func NewGroupsCollector(account, token string, budget *collect.Budget) *GroupsCollector {
	return &GroupsCollector{account: account, api: &oktaClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newGroupsCollector(account string, api oktaAPI) *GroupsCollector {
	return &GroupsCollector{account: account, api: api}
}

func (c *GroupsCollector) ID() string               { return groupsCollectorID }
func (c *GroupsCollector) Provider() model.Provider { return model.Okta }

func groupsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Okta, Profile: permissions.Discovery, Permission: "okta.users.read", By: groupsCollectorID},
		{Provider: model.Okta, Profile: permissions.Discovery, Permission: "okta.groups.read", By: groupsCollectorID},
	}
}

func init() {
	for _, r := range groupsRequirements() {
		permissions.Declare(r)
	}
}

func (c *GroupsCollector) Requirements() []permissions.Requirement { return groupsRequirements() }

type oktaGroup struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

// Collect lists groups, emits a node per group, then for each group lists its members and
// emits member_of edges. It records completeness: Complete when every group's members were
// read, Partial when some group's read was denied or throttled, Denied when the group
// listing itself was denied.
func (c *GroupsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "groups"
	scope := collect.Scope{Account: c.account}

	groups, denied := c.listGroups(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}
	degraded := ""
	memberships := 0
	for _, g := range groups {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: len(groups), Reason: "cancelled"})
			return err
		}
		n, err := c.groupMembers(ctx, sink, g.ID)
		memberships += n
		if err != nil && degraded == "" {
			degraded = redact.String(err.Error())
		}
	}
	status := collect.Complete
	if degraded != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: len(groups), Reason: degraded})
}

func (c *GroupsCollector) listGroups(ctx context.Context, sink collect.Sink) ([]oktaGroup, string) {
	url := fmt.Sprintf("%s/api/v1/groups?limit=%d", c.account, pageLimit)
	var out []oktaGroup
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return out, "budget exhausted"
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			return nil, redact.String(err.Error())
		}
		_ = sink.Evidence(evidence(c.account, "groups", "groups.list", groupsCollectorID, body))
		var groups []oktaGroup
		if err := json.Unmarshal(body, &groups); err != nil {
			return nil, redact.String(err.Error())
		}
		for _, g := range groups {
			if g.ID == "" {
				continue
			}
			_ = sink.Node(collect.Node{
				Type: model.NodeGroup, NativeID: groupID(g.ID), Name: g.Profile.Name,
				Attributes: attrs("type", g.Type, "description", g.Profile.Description),
			})
			out = append(out, g)
		}
		if next == "" {
			break
		}
		url = next
	}
	return out, ""
}

// groupMembers lists one group's member users and emits a member_of edge per member. It
// returns the count and any read error, which the caller aggregates into a Partial reason.
func (c *GroupsCollector) groupMembers(ctx context.Context, sink collect.Sink, gid string) (int, error) {
	url := fmt.Sprintf("%s/api/v1/groups/%s/users?limit=%d", c.account, gid, pageLimit)
	count := 0
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return count, fmt.Errorf("budget exhausted before group %s members", gid)
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			return count, fmt.Errorf("group %s members: %w", gid, err)
		}
		_ = sink.Evidence(evidence(c.account, "groups", "groups.members", groupsCollectorID, body))
		var members []oktaUser
		if err := json.Unmarshal(body, &members); err != nil {
			return count, fmt.Errorf("group %s members: %w", gid, err)
		}
		for _, m := range members {
			if m.ID == "" {
				continue
			}
			_ = sink.Link(collect.Link{SourceNativeID: userID(m.ID), TargetNativeID: groupID(gid), Kind: model.EdgeMemberOf})
		}
		count += len(members)
		if next == "" {
			break
		}
		url = next
	}
	return count, nil
}
