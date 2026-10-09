package store

import (
	"encoding/json"
	"strconv"
	"strings"
)

// volatileAttr reports whether an attribute key holds a value that changes on its
// own over time (an age in days, or an expiry countdown) rather than only when the
// resource itself changes. Such facts are excluded from the entity content hash, so a
// pure daily age tick is not reported as a change by the later-scan change detector
// (AGE-FACTS-2). The full attribute map is still sealed and stored; only the
// change-detection hash ignores these keys. The convention: a key ending in
// "_age_days" (key_age_days, role_last_used_age_days, cred_access_key_1_age_days, ...)
// or the exact key "days_until_expiry". A static derived fact like
// credential_lifetime_days is not volatile and stays in the hash.
func volatileAttr(key string) bool {
	return strings.HasSuffix(key, "_age_days") || key == "days_until_expiry"
}

// stableAttributes returns m without volatile keys, for the content hash only. It
// returns m unchanged when there is nothing to strip, so non-volatile entities keep
// their exact prior bytes and hash.
func stableAttributes(m map[string]string) map[string]string {
	hasVolatile := false
	for key := range m {
		if volatileAttr(key) {
			hasVolatile = true
			break
		}
	}
	if !hasVolatile {
		return m
	}
	out := make(map[string]string, len(m))
	for key, v := range m {
		if !volatileAttr(key) {
			out[key] = v
		}
	}
	return out
}

// canonicalMap serialises a string map deterministically, returning nil for an
// empty or nil map. encoding/json sorts map keys, so the bytes depend only on
// the contents, never the map's iteration order. It is the single source for
// both a value's content hash and its sealed bytes, so the two can never
// disagree about what "changed" means (B-1). An empty map seals to NULL and
// contributes an empty string to the hash, so nil and empty are one state.
func canonicalMap(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return nil, nil
	}
	return json.Marshal(m)
}

// entityContentHash is the keyed hash over an entity's mutable content
// (ADR-0011 §1): every field that a later scan can change, in plaintext,
// because random-nonce sealing makes ciphertext non-deterministic. tags are the
// canonical bytes from canonicalMap; attributes are the canonical bytes of the
// STABLE attribute view (stableAttributes), so volatile facts that tick on their
// own (ages, expiry countdowns) do not flip change detection (AGE-FACTS-2) even
// though the full map is still sealed. native_id is the
// identity basis and never changes, but is covered for completeness. It is
// shared by the first-scan loader and later-scan change detection, so a value
// hashes identically however it was written.
func entityContentHash(k *tenantKeys, provider, nodeType, criticality int64, nativeID, name string, tags, attributes []byte) []byte {
	return k.hash(hashEntityContent,
		strconv.FormatInt(provider, 10), strconv.FormatInt(nodeType, 10),
		nativeID, name, strconv.FormatInt(criticality, 10),
		string(tags), string(attributes))
}

// edgeContentHash is the keyed hash over an edge's mutable content: the
// confidence and the conditions (B-1). kind, src, and dst are the edge's
// identity, not its content, so they are not hashed here. conditions is the
// canonical bytes from canonicalMap.
func edgeContentHash(k *tenantKeys, confidence int64, conditions []byte) []byte {
	return k.hash(hashEdgeContent, strconv.FormatInt(confidence, 10), string(conditions))
}

// itoa formats an integer for a keyed hash input.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// A permission is identified by who may take which action on what (principal,
// resource, action); its effect, conditions, and inheritance are content, so a
// flipped effect is a change to the same permission, not a new one. Identity
// uses the entities' stable IDs, so it survives across scans even as node IDs
// are reassigned.
func permissionIdentity(k *tenantKeys, principalSID, resourceSID []byte, action string) []byte {
	return k.hash(hashPermissionID, string(principalSID), string(resourceSID), action)
}

func permissionContentHash(k *tenantKeys, effect int64, condition, inheritedSID []byte) []byte {
	return k.hash(hashPermissionContent, itoa(effect), string(condition), string(inheritedSID))
}

// An exposure is identified by the reachable node, the source zone, the
// protocol, and the port range; whether authentication is required, whether it
// is effective, and the trace are content.
func exposureIdentity(k *tenantKeys, nodeSID []byte, zone, protocol, portFrom, portTo int64) []byte {
	return k.hash(hashExposureID, string(nodeSID), itoa(zone), itoa(protocol), itoa(portFrom), itoa(portTo))
}

func exposureContentHash(k *tenantKeys, authRequired, effective int64, trace []byte) []byte {
	return k.hash(hashExposureContent, itoa(authRequired), itoa(effective), string(trace))
}

// A classification is identified by its node, label, and method; its confidence
// and approved sample are content.
func classificationIdentity(k *tenantKeys, nodeSID []byte, label, method string) []byte {
	return k.hash(hashClassification, string(nodeSID), label, method)
}

func classificationContentHash(k *tenantKeys, confidence int64, sample []byte) []byte {
	return k.hash(hashClassificationContent, itoa(confidence), string(sample))
}
