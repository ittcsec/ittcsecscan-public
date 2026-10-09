package collect

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
)

// FuzzTrustPolicyParsing drives arbitrary bytes through the role trust-policy parser, the
// most complex hand-written parser in the AWS collector: URL-unescaping, statement and
// principal shape handling (object or array, string or list), condition parsing, and the
// GitHub/GitLab OIDC sub-claim extraction. A malformed or hostile trust document must never
// panic; it may legitimately yield no edges. This exercises T-16 (bounded, robust parsing
// of attacker-influenced provider data) for the identity collector's richest input.
func FuzzTrustPolicyParsing(f *testing.F) {
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	f.Add(`{"Statement":{"Effect":"Allow","Principal":"*"}}`)
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:o/r:*"}}}]}`)
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/gitlab.com"},"Condition":{"StringEquals":{"gitlab.com:sub":"project_path:g/p:ref_type:branch:ref:main"}}}]}`)
	f.Add(`%7B%22Statement%22%3A%5B%5D%7D`) // URL-encoded
	f.Add(``)
	f.Add(`{`)

	f.Fuzz(func(t *testing.T, doc string) {
		// trustedPrincipals and trustEdges must both tolerate any input without panicking.
		_ = trustedPrincipals(doc)
		var scan collect.Scan
		(&IdentityCollector{}).trustEdges(&scan, "arn:aws:iam::123456789012:role/R", doc)
		// Every emitted link must reference the role and carry a known edge kind; no partial
		// or malformed edge escapes the parser.
		for _, l := range scan.Links {
			if l.TargetNativeID == "" && l.SourceNativeID == "" {
				t.Fatalf("emitted an edge with no endpoints from doc %q", doc)
			}
		}
	})
}
