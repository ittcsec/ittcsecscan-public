package collect

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

func userID(id string) string  { return "gws:user:" + id }
func groupID(id string) string { return "gws:group:" + id }

// pageURL builds a Directory list URL with the customer, page size, and optional page
// token. token is URL-query-escaped.
func pageURL(path, token string) string {
	u := fmt.Sprintf("%s%s?customer=%s&maxResults=%d", directoryBaseURL, path, customerAlias, pageSize)
	if token != "" {
		u += "&pageToken=" + url.QueryEscape(token)
	}
	return u
}

func completenessFor(service string, scope collect.Scope, count int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: count, Reason: redact.String(err.Error())}
}

func evidence(account, service, operation, collectorID string, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.GoogleWorkspace, Service: service, Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: collect.Scope{Account: account},
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "directory_v1", Collector: collectorID},
	}
}

func attrs(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

func boolAttr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
