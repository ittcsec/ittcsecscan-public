package collect

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

const (
	// pageLimit is the list page size requested via ?limit.
	pageLimit = 500
	// maxPages bounds how many pages a listing will follow, so an endpoint that returns
	// a continue token forever cannot hang the scan. Hitting it is a represented Partial
	// gap.
	maxPages = 1000
)

// lister carries what every Kubernetes collector needs to page through a list endpoint:
// the cluster account (API server URL), the read-only API client, and the scan's shared
// call budget.
type lister struct {
	account string
	api     API
	budget  *collect.Budget
}

// listPage is a Kubernetes list response: the continue token in metadata and the raw
// items, left undecoded so each collector parses only the fields it needs.
type listPage struct {
	Metadata listMeta          `json:"metadata"`
	Items    []json.RawMessage `json:"items"`
}

// paginate GETs every page of basePath (following metadata.continue), records one
// evidence envelope per page, and returns the raw items and a represented completeness.
// A denied or throttled read yields the matching gap; a decode failure is Errored; a
// full read is Complete. It never reports Complete when a page failed.
func (l lister) paginate(ctx context.Context, sink collect.Sink, service, collectorID, basePath, operation string) ([]json.RawMessage, collect.Completeness) {
	scope := collect.Scope{Account: l.account}
	var items []json.RawMessage
	cont := ""
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return items, comp(service, scope, collect.Partial, len(items), "cancelled")
		}
		if !l.budget.Spend() {
			return items, comp(service, scope, collect.Partial, len(items), "budget exhausted")
		}
		u := basePath + "?limit=" + strconv.Itoa(pageLimit)
		if cont != "" {
			u += "&continue=" + url.QueryEscape(cont)
		}
		body, err := l.api.Get(ctx, u)
		if err != nil {
			return items, completenessFor(service, scope, len(items), err)
		}
		_ = sink.Evidence(evidence(l.account, service, operation, collectorID, body))
		var pg listPage
		if err := json.Unmarshal(body, &pg); err != nil {
			return items, comp(service, scope, collect.Errored, len(items), redact.String(err.Error()))
		}
		items = append(items, pg.Items...)
		cont = pg.Metadata.Continue
		if cont == "" {
			return items, comp(service, scope, collect.Complete, len(items), "")
		}
	}
	return items, comp(service, scope, collect.Partial, len(items), "page limit reached")
}

// completenessFor maps a failed read to a represented gap: Denied for a 403/401, Partial
// for a throttle, Errored otherwise. It never reports Complete on failure.
func completenessFor(service string, scope collect.Scope, count int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return comp(service, scope, status, count, redact.String(err.Error()))
}

func comp(service string, scope collect.Scope, status collect.Status, count int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: count, Reason: reason}
}

// evidence builds the evidence envelope for a Kubernetes read: the response is redacted
// and stamped with provider, service, operation, scope, and provenance.
func evidence(account, service, operation, collectorID string, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Kubernetes, Service: service, Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: collect.Scope{Account: account},
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "v1", Collector: collectorID},
	}
}

// objectMeta is the subset of a Kubernetes object's metadata the collectors read.
type objectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
}

// Native-id helpers give each object a typed, self-describing key that cannot collide
// with another provider's ids and that the RBAC collector reconstructs to join a binding
// to its subject and role.
func namespaceID(name string) string { return "namespace:" + name }

func serviceAccountID(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}

func roleID(namespace, name string) string { return "role:" + namespace + ":" + name }

func clusterRoleID(name string) string { return "clusterrole:" + name }

// attrs builds an attribute map from key/value pairs, dropping empty values so a node
// carries only the facts actually present.
func attrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}
