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

const usersCollectorID = "collector:google_workspace.users"

// UsersCollector reads a Workspace customer's users: GET /users?customer=my_customer
// (paginated by nextPageToken), a read-only call verified against the Admin SDK Directory
// API that returns profile metadata, no credential. It emits one identity node per user,
// keyed by the Directory user id, so group memberships join to the same identity.
type UsersCollector struct {
	account string
	api     gwsAPI
	budget  *collect.Budget
}

func NewUsersCollector(account, token string, budget *collect.Budget) *UsersCollector {
	return &UsersCollector{account: account, api: &gwsClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newUsersCollector(account string, api gwsAPI) *UsersCollector {
	return &UsersCollector{account: account, api: api}
}

func (c *UsersCollector) ID() string               { return usersCollectorID }
func (c *UsersCollector) Provider() model.Provider { return model.GoogleWorkspace }

func usersRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.GoogleWorkspace, Profile: permissions.Discovery, Permission: "admin.directory.user.readonly", By: usersCollectorID},
	}
}

func init() {
	for _, r := range usersRequirements() {
		permissions.Declare(r)
	}
}

func (c *UsersCollector) Requirements() []permissions.Requirement { return usersRequirements() }

type usersPage struct {
	Users []struct {
		ID           string `json:"id"`
		PrimaryEmail string `json:"primaryEmail"`
		Name         struct {
			FullName string `json:"fullName"`
		} `json:"name"`
		Suspended bool `json:"suspended"`
		IsAdmin   bool `json:"isAdmin"`
	} `json:"users"`
	NextPageToken string `json:"nextPageToken"`
}

func (c *UsersCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "users"
	scope := collect.Scope{Account: c.account}
	token := ""
	count := 0
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
		}
		body, err := c.api.get(ctx, pageURL("/users", token))
		if err != nil {
			_ = sink.Complete(completenessFor(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(evidence(c.account, service, "users.list", usersCollectorID, body))
		var pg usersPage
		if err := json.Unmarshal(body, &pg); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, u := range pg.Users {
			if u.ID == "" {
				continue
			}
			_ = sink.Node(collect.Node{
				Type: model.NodeIdentity, NativeID: userID(u.ID), Name: u.PrimaryEmail,
				Attributes: attrs("kind", "User", "email", u.PrimaryEmail, "full_name", u.Name.FullName, "suspended", boolAttr(u.Suspended), "is_admin", boolAttr(u.IsAdmin)),
			})
		}
		count += len(pg.Users)
		token = pg.NextPageToken
		if token == "" {
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Complete, Collected: count})
		}
	}
	return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "page limit reached"})
}
