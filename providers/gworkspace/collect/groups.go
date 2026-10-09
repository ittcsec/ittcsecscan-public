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

const groupsCollectorID = "collector:google_workspace.groups"

// GroupsCollector reads a Workspace customer's groups and their memberships: GET /groups,
// then GET /groups/{groupKey}/members per group, both read-only calls verified against the
// Admin SDK Directory API. It emits one group node per group and a member_of edge from each
// member (a user, keyed by the same Directory user id the users collector emits, or a
// nested group) to the group, so the identity-to-group graph joins in one scan.
type GroupsCollector struct {
	account string
	api     gwsAPI
	budget  *collect.Budget
}

func NewGroupsCollector(account, token string, budget *collect.Budget) *GroupsCollector {
	return &GroupsCollector{account: account, api: &gwsClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newGroupsCollector(account string, api gwsAPI) *GroupsCollector {
	return &GroupsCollector{account: account, api: api}
}

func (c *GroupsCollector) ID() string               { return groupsCollectorID }
func (c *GroupsCollector) Provider() model.Provider { return model.GoogleWorkspace }

func groupsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GoogleWorkspace, Profile: permissions.Discovery, Permission: "admin.directory.group.readonly", By: groupsCollectorID},
		{Provider: model.GoogleWorkspace, Profile: permissions.Discovery, Permission: "admin.directory.group.member.readonly", By: groupsCollectorID},
	}
}

func init() {
	for _, r := range groupsRequirements() {
		permissions.Declare(r)
	}
}

func (c *GroupsCollector) Requirements() []permissions.Requirement { return groupsRequirements() }

type groupsPage struct {
	Groups []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"groups"`
	NextPageToken string `json:"nextPageToken"`
}

type membersPage struct {
	Members []struct {
		ID   string `json:"id"`
		Type string `json:"type"` // USER | GROUP
	} `json:"members"`
	NextPageToken string `json:"nextPageToken"`
}

// Collect lists groups (emitting a node per group), then each group's members (emitting
// member_of edges). Completeness: Complete when every group's members were read, Partial
// when some group's read was denied or throttled, Denied when the group listing was denied.
func (c *GroupsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "groups"
	scope := collect.Scope{Account: c.account}

	groupIDs, denied := c.listGroups(ctx, sink)
	if denied != "" {
		return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Denied, Reason: denied})
	}
	degraded := ""
	for _, gid := range groupIDs {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: len(groupIDs), Reason: "cancelled"})
			return err
		}
		if err := c.groupMembers(ctx, sink, gid); err != nil && degraded == "" {
			degraded = redact.String(err.Error())
		}
	}
	status := collect.Complete
	if degraded != "" {
		status = collect.Partial
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: len(groupIDs), Reason: degraded})
}

func (c *GroupsCollector) listGroups(ctx context.Context, sink collect.Sink) ([]string, string) {
	token := ""
	var ids []string
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return ids, "budget exhausted"
		}
		body, err := c.api.get(ctx, pageURL("/groups", token))
		if err != nil {
			return nil, redact.String(err.Error())
		}
		_ = sink.Evidence(evidence(c.account, "groups", "groups.list", groupsCollectorID, body))
		var pg groupsPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, redact.String(err.Error())
		}
		for _, g := range pg.Groups {
			if g.ID == "" {
				continue
			}
			_ = sink.Node(collect.Node{Type: model.NodeGroup, NativeID: groupID(g.ID), Name: g.Email, Attributes: attrs("email", g.Email, "display_name", g.Name)})
			ids = append(ids, g.ID)
		}
		token = pg.NextPageToken
		if token == "" {
			break
		}
	}
	return ids, ""
}

// groupMembers lists one group's members and emits a member_of edge per member. A USER
// member joins to the user identity; a nested GROUP member joins to the group node.
func (c *GroupsCollector) groupMembers(ctx context.Context, sink collect.Sink, gid string) error {
	token := ""
	for page := 0; page < maxPages; page++ {
		if !c.budget.Spend() {
			return fmt.Errorf("budget exhausted before group %s members", gid)
		}
		body, err := c.api.get(ctx, pageURL("/groups/"+gid+"/members", token))
		if err != nil {
			return fmt.Errorf("group %s members: %w", gid, err)
		}
		_ = sink.Evidence(evidence(c.account, "groups", "groups.members", groupsCollectorID, body))
		var pg membersPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return fmt.Errorf("group %s members: %w", gid, err)
		}
		for _, m := range pg.Members {
			if m.ID == "" {
				continue
			}
			src := userID(m.ID)
			if m.Type == "GROUP" {
				src = groupID(m.ID)
			}
			_ = sink.Link(collect.Link{SourceNativeID: src, TargetNativeID: groupID(gid), Kind: model.EdgeMemberOf})
		}
		token = pg.NextPageToken
		if token == "" {
			break
		}
	}
	return nil
}
