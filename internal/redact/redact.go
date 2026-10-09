// Package redact removes secret material from strings and structured values
// before they reach logs, terminals, or reports.
//
// Redaction is defense in depth. The primary control is that ittcsecscan never
// retrieves or stores secret values in the first place. This package exists so
// that a secret which arrives by accident — inside a provider error message, an
// operator-supplied string, or a misnamed field — is not persisted or displayed.
//
// Redaction deliberately over-matches: losing a harmless word from a log line is
// acceptable, leaking a credential is not.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder replaces every redacted value.
const Placeholder = "[REDACTED]"

type pattern struct {
	name string
	re   *regexp.Regexp
	repl string
}

// patterns are applied in order. Patterns that match a credential together with
// its surrounding syntax (PEM armour, URL userinfo, Authorization schemes) run
// before the generic key=value rule so the generic rule cannot consume only a
// prefix of the secret and leave the remainder in the output.
//
// All patterns are RE2 (linear time); untrusted input cannot cause catastrophic
// backtracking.
var patterns = []pattern{
	{
		name: "pem-private-key",
		re:   regexp.MustCompile(`-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END[A-Z0-9 ]*PRIVATE KEY-----|$)`),
		repl: Placeholder,
	},
	{
		name: "url-userinfo",
		re:   regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]*:[^/\s@]*@`),
		repl: "${1}" + Placeholder + "@",
	},
	{
		name: "authorization-scheme",
		re:   regexp.MustCompile(`(?i)\b(bearer|basic|negotiate|ssws)\s+[A-Za-z0-9\-._~+/]{16,}=*`),
		repl: "${1} " + Placeholder,
	},
	{
		name: "jwt",
		re:   regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`),
		repl: Placeholder,
	},
	{
		name: "github-token",
		re:   regexp.MustCompile(`(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}`),
		repl: Placeholder,
	},
	{
		// GitLab tokens share a "gl<kind>-" prefix (glpat- personal, gldt- deploy,
		// glrt- runner, glptt- pipeline-trigger, glsoat- and others) followed by the
		// token material. The unbounded quantifier consumes the whole secret.
		name: "gitlab-token",
		re:   regexp.MustCompile(`gl[a-z]{2,7}-[A-Za-z0-9_-]{20,}`),
		repl: Placeholder,
	},
	{
		name: "slack-token",
		re:   regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`),
		repl: Placeholder,
	},
	{
		name: "google-api-key",
		re:   regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		repl: Placeholder,
	},
	{
		// Long-term (AKIA) and temporary (ASIA) access key IDs. The trailing
		// quantifier is unbounded so adjacent key material is consumed too.
		name: "aws-access-key-id",
		re:   regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,}`),
		repl: Placeholder,
	},
	{
		// GCP OAuth 2.0 access tokens ("ya29." prefix). Opaque, not a JWT, so
		// the jwt rule above does not catch them.
		name: "gcp-access-token",
		re:   regexp.MustCompile(`ya29\.[A-Za-z0-9_-]{20,}`),
		repl: Placeholder,
	},
	{
		// GCP / Google OAuth refresh tokens ("1//" prefix). Long-lived and more
		// sensitive than an access token. The "1//" + long URL-safe tail shape is
		// distinctive enough that ordinary text does not match.
		name: "gcp-refresh-token",
		re:   regexp.MustCompile(`1//[A-Za-z0-9_-]{20,}`),
		repl: Placeholder,
	},
	{
		// AWS SigV4 request signature ("Signature=<hex>", also inside an
		// Authorization: AWS4-HMAC-SHA256 header). The key is kept; the hex
		// signature is derived auth material and is redacted. The Credential=
		// component is handled by the access-key-id rule above.
		name: "aws-sigv4-signature",
		re:   regexp.MustCompile(`(?i)(signature)(\s*[=:]\s*)([0-9a-f]{16,})`),
		repl: "${1}${2}" + Placeholder,
	},
	{
		// key=value, key: value, "key": "value", and query parameters such as
		// Azure SAS "sig=". The key is kept so the log line stays diagnosable.
		name: "key-value",
		re: regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|account[_-]?key|sharedaccesskey|credential|client[_-]?assertion)[a-z0-9_.-]*|\bpwd|\bsig)` +
			`("?\s*[=:]\s*)` +
			`("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s"',;&]+)`),
		repl: "${1}${2}" + Placeholder,
	},
}

// maxPasses bounds the fixpoint loop in String. One pass is sufficient for all
// known inputs; the bound exists so a future pattern interaction cannot loop.
const maxPasses = 4

// String returns s with every recognised secret replaced by Placeholder.
// The result is idempotent: String(String(s)) == String(s).
func String(s string) string {
	if s == "" {
		return s
	}
	for range maxPasses {
		next := s
		for _, p := range patterns {
			next = p.re.ReplaceAllString(next, p.repl)
		}
		if next == s {
			return next
		}
		s = next
	}
	return s
}

// sensitiveKeyParts are substrings that mark a field name as secret-bearing
// after normalisation (lower case, separators removed).
var sensitiveKeyParts = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"apikey",
	"accesskey",
	"privatekey",
	"accountkey",
	"sharedaccesskey",
	"credential",
	"authorization",
	"cookie",
	"session",
	"signature",
	"clientassertion",
	"connectionstring",
}

// sensitiveKeys are complete normalised field names that are too short to match
// as substrings without excessive false positives.
var sensitiveKeys = map[string]struct{}{
	"pwd":  {},
	"sig":  {},
	"key":  {},
	"auth": {},
	"sas":  {},
}

// Key reports whether a field name conventionally holds secret material, for
// example "aws_secret_access_key", "Authorization", or "client-secret".
func Key(name string) bool {
	n := normalizeKey(name)
	if n == "" {
		return false
	}
	if _, ok := sensitiveKeys[n]; ok {
		return true
	}
	for _, part := range sensitiveKeyParts {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

func normalizeKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		switch r {
		case '_', '-', '.', ' ':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
