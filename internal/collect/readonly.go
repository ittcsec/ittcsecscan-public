package collect

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Forbidden is the deny-list of provider operations a collector must never call
// (ADR-0018 §1): secret-value and key-material retrievals and object-content
// reads. It is the secondary read-only control; the least-privilege credential
// is the primary one, and evidence redaction is the final net.
//
// The list is keyed by the operation's **method name** and matching is by method
// name, as a linter without type information would do. That constrains SDK-based
// call sites, where the operation is a method (the AWS collectors use the AWS SDK,
// so the entries below bite them). A plain-HTTP call, where the operation is
// encoded in a URL passed to a shared helper (`azureGet`, `gcpDo`), does not have
// a matching method name; those are caught by ForbiddenPaths (URL fragments)
// instead. Only method names that a collector could actually call in this codebase
// are listed, so the deny-list does not imply coverage it cannot provide; it grows
// as each SDK-based service is collected.
//
// It carries one synthetic entry, forbiddenSyntheticWrite, kept permanently so
// the gate is proven to bite now rather than being first exercised by a real
// collector (see TestReadOnlyGateBites). A future benign method-name collision is
// handled when it arises.
var Forbidden = map[string]string{ //nolint:gosec // G101: keys are provider operation names (e.g. GetPasswordData) that the gate refuses, not credentials
	"forbiddenSyntheticWrite": "synthetic forbidden operation, kept to prove the gate bites",

	// Secret values and key material are never retrieved (AWS SDK operations).
	"Decrypt":             "returns plaintext (kms:Decrypt)",
	"GenerateDataKey":     "returns a plaintext data key (kms:GenerateDataKey)",
	"GenerateDataKeyPair": "returns a plaintext private key (kms:GenerateDataKeyPair)",
	"GetSecretValue":      "returns a secret value (secretsmanager:GetSecretValue)",
	"BatchGetSecretValue": "returns secret values (secretsmanager:BatchGetSecretValue)",

	// EC2 secret material and content (verified against the EC2 API reference,
	// 2026-09-19). An instance's password, console output, console screenshot, and
	// user data are never read; user data is a common place for embedded secrets.
	// DescribeInstanceAttribute and DescribeLaunchTemplateVersions can return user
	// data alongside metadata, so those method names are refused outright (ADR-0019
	// "Revisit when": metadata coupled with content).
	"GetPasswordData":                "returns an instance's encrypted administrator password (ec2:GetPasswordData)",
	"GetConsoleOutput":               "returns instance console output (ec2:GetConsoleOutput)",
	"GetConsoleScreenshot":           "returns an instance console screenshot (ec2:GetConsoleScreenshot)",
	"GetLaunchTemplateData":          "returns launch data including user data (ec2:GetLaunchTemplateData)",
	"DescribeInstanceAttribute":      "can return instance user data (ec2:DescribeInstanceAttribute)",
	"DescribeLaunchTemplateVersions": "returns launch template data including user data (ec2:DescribeLaunchTemplateVersions)",

	// Object contents are never read; only object and bucket metadata is in scope.
	"GetObject":           "reads object contents (s3:GetObject)",
	"SelectObjectContent": "reads object contents (s3:SelectObjectContent)",

	// AWS Organizations write operations (verified against the Organizations API
	// reference, 2026-09-22). The hierarchy collector reads Describe/List only; the
	// Organizations API also exposes genuinely destructive actions that nothing this
	// tool collects must ever call: creating, moving, closing, or removing accounts;
	// inviting accounts and handshakes; and creating, deleting, attaching, or
	// modifying policies (SCPs). Refused outright as defence in depth beside the
	// least-privilege credential.
	"CreateAccount":                 "creates a member account (organizations:CreateAccount)",
	"CloseAccount":                  "closes a member account (organizations:CloseAccount)",
	"MoveAccount":                   "moves an account between parents (organizations:MoveAccount)",
	"RemoveAccountFromOrganization": "removes an account from the org (organizations:RemoveAccountFromOrganization)",
	"InviteAccountToOrganization":   "invites an account to the org (organizations:InviteAccountToOrganization)",
	"CreateOrganization":            "creates an organization (organizations:CreateOrganization)",
	"DeleteOrganization":            "deletes the organization (organizations:DeleteOrganization)",
	"LeaveOrganization":             "removes this account from its org (organizations:LeaveOrganization)",
	"CreateOrganizationalUnit":      "creates an OU (organizations:CreateOrganizationalUnit)",
	"DeleteOrganizationalUnit":      "deletes an OU (organizations:DeleteOrganizationalUnit)",
	"UpdateOrganizationalUnit":      "renames an OU (organizations:UpdateOrganizationalUnit)",
	"CreatePolicy":                  "creates a policy such as an SCP (organizations:CreatePolicy)",
	"DeletePolicy":                  "deletes a policy (organizations:DeletePolicy)",
	"UpdatePolicy":                  "modifies a policy (organizations:UpdatePolicy)",
	"AttachPolicy":                  "attaches a policy such as an SCP (organizations:AttachPolicy)",
	"DetachPolicy":                  "detaches a policy (organizations:DetachPolicy)",
	"EnablePolicyType":              "enables a policy type on a root (organizations:EnablePolicyType)",
	"DisablePolicyType":             "disables a policy type on a root (organizations:DisablePolicyType)",
	"EnableAllFeatures":             "enables all org features (organizations:EnableAllFeatures)",
	"AcceptHandshake":               "accepts an org handshake (organizations:AcceptHandshake)",
	"DeclineHandshake":              "declines an org handshake (organizations:DeclineHandshake)",
	"CancelHandshake":               "cancels an org handshake (organizations:CancelHandshake)",
}

// ForbiddenPaths is the deny-list for the plain-HTTP providers (GCP, Azure), whose
// operation is encoded in a request URL rather than a method name, so the method
// name gate (Forbidden) cannot see it. Each entry is a URL fragment that, if it
// appears in a string literal in the source, marks a content or secret-value read;
// checkSource flags any string literal containing one. Each fragment is chosen to
// hit the value/content read while leaving the metadata and list reads untouched
// (verified against the provider API references, 2026-09-20):
//
//   - "alt=media": a GCS objects.get with alt=media returns the object's content;
//     without it the same call returns only metadata.
//   - ":access": a Secret Manager versions access ("versions/*:access") returns the
//     secret payload; listing secrets and versions returns metadata, no ":access".
//   - "entries:list" / "entries:tail": a Cloud Logging entries read returns log
//     entry contents; the logging collector reads only sink and bucket config, whose
//     paths ("/sinks", "/buckets") never contain "entries:".
//
// This is the same defence layer as Forbidden and the same threat model: it catches
// an ACCIDENTAL content or secret read in source, not a deliberate evasion (a URL
// assembled to avoid the literal fragment, e.g. "/sec"+"rets/", would slip past,
// exactly as a reflection-built method call slips past Forbidden). The synthetic
// entry proves it bites now (see TestReadOnlyPathGateBites). The set grows per
// plain-HTTP service; each entry is precise, hitting the content or secret read while
// leaving the GCP and Azure metadata and list reads untouched.
//
// Deferred, by design (both Azure, both further out): a bare "/secrets/" fragment
// for Azure Key Vault's value read is NOT included, because it also matches GCP
// Secret Manager's metadata paths (".../secrets/{secret}", ".../versions") which
// are allowed reads, so it is not precisely targeted; it needs a host-qualified
// form (or the collector's own guard) that the Key Vault collector will settle when
// built. Azure Blob object content likewise has no distinctive URL fragment (a
// content GET is the default blob GET) and is left to the Blob collector's design.
var ForbiddenPaths = map[string]string{ //nolint:gosec // G101: these are URL fragments the gate REFUSES, not credentials
	":forbiddenSyntheticContent": "synthetic forbidden URL fragment, kept to prove the path gate bites",

	"alt=media":    "reads object contents (GCS objects.get?alt=media)",
	":access":      "returns a secret payload (Secret Manager versions access)",
	"entries:list": "reads log entry contents (Cloud Logging entries.list)",
	"entries:tail": "reads log entry contents (Cloud Logging entries.tail)",

	// GitHub (and similar verb-based-write providers) expose content and secrets by
	// URL path, not by a distinctive SDK method name, so the content/secret gate is
	// enforced here (ADR-0031 section 2). A GitHub collector must never read file
	// contents, Actions secrets, or raw git objects.
	"/contents/":       "reads repository file contents (GitHub repos.getContent)",
	"/actions/secrets": "reads or lists Actions secrets (GitHub actions secrets API)",
	"/git/blobs":       "reads raw git object contents (GitHub git blobs API)",

	// GitLab is likewise verb-based over URL paths (ADR-0031 section 2). A GitLab
	// collector must never read repository file contents, raw blobs, repository
	// archives, or CI/CD variables (which hold secret material). It reads only
	// project, pipeline, and job metadata.
	"/repository/files/":  "reads repository file contents (GitLab repository files API)",
	"/repository/blobs/":  "reads raw git object contents (GitLab repository blobs API)",
	"/repository/archive": "downloads a repository archive (GitLab repository archive API)",
	"/variables":          "reads CI/CD variables, which hold secret material (GitLab variables API)",

	// Kubernetes is verb-based over URL paths (ADR-0031 section 2). A Kubernetes
	// collector reads only object metadata (namespaces, service accounts, RBAC roles
	// and bindings); it must never read Secret objects (a Secret list returns the
	// base64 data, not just metadata) or open the exec, attach, or port-forward
	// subresources (a live channel into a workload). These fragments are chosen to be
	// specific to Kubernetes so they do not collide with other providers' allowed reads
	// (a bare "/secrets" would match Azure Key Vault's allowed metadata listing, and
	// "/log" would match GCP logging's "/logs" paths); the namespaced Secret path is
	// additionally guarded by the collector set never constructing it.
	"/api/v1/secrets": "reads Secret object values (Kubernetes core secrets API)",
	"/exec":           "opens an exec channel into a container (Kubernetes exec subresource)",
	"/attach":         "attaches to a running container (Kubernetes attach subresource)",
	"/portforward":    "opens a port-forward channel to a Pod (Kubernetes portforward subresource)",
}

// Violation is one forbidden operation found in the source.
type Violation struct {
	File      string
	Line      int
	Operation string
	Reason    string
}

// checkSource parses one Go source and returns the forbidden method calls in it.
// An unparseable source yields no violations; the compiler catches that
// separately.
func checkSource(fset *token.FileSet, filename, src string) []Violation {
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil
	}
	var out []Violation
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// A forbidden SDK operation, matched by method name.
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if reason, forbidden := Forbidden[sel.Sel.Name]; forbidden {
					pos := fset.Position(sel.Sel.Pos())
					out = append(out, Violation{File: filename, Line: pos.Line, Operation: sel.Sel.Name, Reason: reason})
				}
			}
		case *ast.BasicLit:
			// A forbidden plain-HTTP operation, matched by a URL fragment in a string
			// literal (the operation a plain-HTTP call encodes in its URL).
			if node.Kind != token.STRING {
				return true
			}
			s := node.Value
			if unq, err := strconv.Unquote(s); err == nil {
				s = unq
			}
			for _, frag := range sortedKeys(ForbiddenPaths) {
				if strings.Contains(s, frag) {
					pos := fset.Position(node.Pos())
					out = append(out, Violation{File: filename, Line: pos.Line, Operation: frag, Reason: ForbiddenPaths[frag]})
				}
			}
		}
		return true
	})
	return out
}

// sortedKeys returns a map's keys sorted, so a literal matching more than one
// fragment produces violations in a deterministic order.
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// CheckDir walks root's non-test Go source and returns every forbidden operation
// call. vendor and testdata directories are skipped. It is the gate: a collector
// that calls a forbidden operation is a failing test, not a review catch.
func CheckDir(root string) ([]Violation, error) {
	fset := token.NewFileSet()
	var out []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Skip this gate's own definition: it declares the deny-lists, so its
		// ForbiddenPaths keys appear here as string literals and would self-match the
		// path scan. It makes no provider call or URL of its own.
		if d.Name() == "readonly.go" {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from walking a source tree given by the caller, not from untrusted input
		if err != nil {
			return err
		}
		out = append(out, checkSource(fset, path, string(data))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}
