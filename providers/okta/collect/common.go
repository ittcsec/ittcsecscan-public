package collect

import (
	"encoding/json"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// userID and groupID give each object a typed, self-describing native id that cannot
// collide with another provider's ids and lets the users and groups collectors join.
func userID(id string) string  { return "okta:user:" + id }
func groupID(id string) string { return "okta:group:" + id }

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
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: count, Reason: redact.String(err.Error())}
}

func evidence(account, service, operation, collectorID string, response []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Okta, Service: service, Operation: operation, Region: collect.Global,
		CollectedAt: time.Now().UTC(), Scope: collect.Scope{Account: account},
		Response:   json.RawMessage(redact.String(string(response))),
		Provenance: collect.Provenance{APIVersion: "v1", Collector: collectorID},
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
