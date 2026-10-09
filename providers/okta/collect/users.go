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

const usersCollectorID = "collector:okta.users"

// UsersCollector reads an Okta org's users: GET /api/v1/users (Link-paginated), a
// read-only call verified against the Okta Users API that returns profile metadata, no
// credential. It emits one identity node per user, keyed by the Okta user id, so group
// memberships and later access edges join to the same identity.
type UsersCollector struct {
	account string
	api     oktaAPI
	budget  *collect.Budget
}

func NewUsersCollector(account, token string, budget *collect.Budget) *UsersCollector {
	return &UsersCollector{account: account, api: &oktaClient{token: token, http: sharedHTTPClient}, budget: budget}
}

func newUsersCollector(account string, api oktaAPI) *UsersCollector {
	return &UsersCollector{account: account, api: api}
}

func (c *UsersCollector) ID() string               { return usersCollectorID }
func (c *UsersCollector) Provider() model.Provider { return model.Okta }

func usersRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Okta, Profile: permissions.Discovery, Permission: "okta.users.read", By: usersCollectorID},
	}
}

func init() {
	for _, r := range usersRequirements() {
		permissions.Declare(r)
	}
}

func (c *UsersCollector) Requirements() []permissions.Requirement { return usersRequirements() }

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

func (c *UsersCollector) Collect(ctx context.Context, sink collect.Sink) error {
	const service = "users"
	scope := collect.Scope{Account: c.account}
	url := fmt.Sprintf("%s/api/v1/users?limit=%d", c.account, pageLimit)
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "page limit reached"})
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "cancelled"})
			return err
		}
		if !c.budget.Spend() {
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Partial, Collected: count, Reason: "budget exhausted"})
		}
		body, next, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(completenessFor(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(evidence(c.account, service, "users.list", usersCollectorID, body))
		var users []oktaUser
		if err := json.Unmarshal(body, &users); err != nil {
			_ = sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Errored, Collected: count, Reason: redact.String(err.Error())})
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		for _, u := range users {
			if u.ID == "" {
				continue
			}
			_ = sink.Node(collect.Node{
				Type: model.NodeIdentity, NativeID: userID(u.ID), Name: u.Profile.Login,
				Attributes: attrs("kind", "User", "status", u.Status, "email", u.Profile.Email, "first_name", u.Profile.FirstName, "last_name", u.Profile.LastName),
			})
		}
		count += len(users)
		if next == "" {
			return sink.Complete(collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: collect.Complete, Collected: count})
		}
		url = next
	}
}
