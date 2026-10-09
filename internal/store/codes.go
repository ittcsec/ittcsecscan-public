package store

// Stored codes (ADR-0011 §4): types, kinds, and states are small integers in
// tenant files. A name's code is its position in its list plus one, so 0 is
// never a code. The lists are part of the file format: they only ever grow at
// the end, and a test pins every entry.
type codeList []string

// code returns name's code.
func (l codeList) code(name string) (int64, bool) {
	for i, n := range l {
		if n == name {
			return int64(i) + 1, true
		}
	}
	return 0, false
}

// valid reports whether c is a code in l.
func (l codeList) valid(c int64) bool { return c >= 1 && c <= int64(len(l)) }

// name returns the name for code c, the reverse of code.
func (l codeList) name(c int64) (string, bool) {
	if !l.valid(c) {
		return "", false
	}
	return l[c-1], true
}

var (
	// providerCodes are the providers of the required first domains.
	providerCodes = codeList{"aws", "azure", "gcp", "github", "gitlab", "kubernetes", "okta", "google_workspace", "mcp"}

	// nodeTypeCodes are the node types of the canonical model.
	nodeTypeCodes = codeList{
		"account", "subscription", "project", "organization", "tenant",
		"identity", "group", "role", "policy", "credential", "token",
		"workload", "compute", "network", "endpoint", "gateway", "api",
		"data_store", "secret_store", "repository", "pipeline", "artifact",
		"cluster", "namespace", "service", "ai_model", "ai_agent",
		"mcp_server", "tool", "endpoint_device", "vulnerability", "control",
		"business_asset",
	}

	// edgeKindCodes are the edge types of the canonical model.
	edgeKindCodes = codeList{
		"member_of", "assumes", "can_impersonate", "can_create_credential",
		"can_modify_policy", "can_execute_on", "can_read", "can_write",
		"can_delete", "can_exfiltrate", "exposed_to", "routes_to",
		"resolves_to", "trusts", "federates_with", "deploys", "builds",
		"contains_secret", "accesses_data", "invokes_tool", "controls_agent",
		"bypasses_control", "monitored_by", "protected_by", "contains",
	}

	// scanStatusCodes: an interrupted scan is incomplete, never completed
	// (threat T-19).
	scanStatusCodes = codeList{"running", "completed", "failed", "incomplete"}

	// changeCodes are the change records of ADR-0011 §1.
	changeCodes = codeList{"appeared", "changed", "disappeared"}

	freshnessCodes    = codeList{"fresh", "stale", "unknown"}
	completenessCodes = codeList{"complete", "partial", "unknown"}

	// outcomeCodes are rule outcomes; unknown and error are never pass.
	outcomeCodes = codeList{"pass", "fail", "unknown", "error", "not_applicable"}

	// scopeReasonCodes distinguish why a scope's coarse completeness is not
	// "complete" (the report contract). They are the non-coverage
	// outcomes of a collection: a permission denial, an unsupported service or
	// region, or an unexpected error. They never override the coarse completeness
	// code, which stays complete/partial/unknown.
	scopeReasonCodes = codeList{"denied", "unsupported", "error"}
)
