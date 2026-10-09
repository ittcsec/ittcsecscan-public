package collect

import (
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestReadOnlyGateBites is the proof the maintainer required: the deny-list actually
// refuses a forbidden operation now, rather than being first exercised by a real
// collector. A synthetic source that calls the synthetic forbidden operation is
// flagged, with the operation named.
func TestReadOnlyGateBites(t *testing.T) {
	src := `package p
type c struct{}
func (c) forbiddenSyntheticWrite() {}
func run() { var x c; x.forbiddenSyntheticWrite() }
`
	got := checkSource(token.NewFileSet(), "synthetic.go", src)
	if len(got) != 1 {
		t.Fatalf("gate did not fire on the forbidden call: %+v", got)
	}
	if got[0].Operation != "forbiddenSyntheticWrite" {
		t.Errorf("operation = %q, want forbiddenSyntheticWrite", got[0].Operation)
	}
}

// TestReadOnlyPathGateBites proves the plain-HTTP path gate bites now: a source
// with a string literal containing the synthetic forbidden URL fragment is
// flagged, with the fragment named.
func TestReadOnlyPathGateBites(t *testing.T) {
	src := `package p
func run() { u := "https://example/api:forbiddenSyntheticContent"; _ = u }
`
	got := checkSource(token.NewFileSet(), "synthetic.go", src)
	if len(got) != 1 || got[0].Operation != ":forbiddenSyntheticContent" {
		t.Fatalf("path gate did not fire on the forbidden URL fragment: %+v", got)
	}
}

// TestForbiddenPathsCatchContentAndSecretURLs proves each real URL fragment flags
// the value/content read while the metadata and list reads are left untouched
// (the plain-HTTP analog of the method-name gate's precision). Hosts are neutral
// placeholders; the gate matches only the operation fragment, and the fixtures
// avoid literal credential-like words so they read as URLs, not secrets.
func TestForbiddenPathsCatchContentAndSecretURLs(t *testing.T) {
	flagged := map[string]string{
		"object media (GCS content)":  "https://storage.googleapis.com/storage/v1/b/bkt/o/obj?alt=media",
		"version access (SM payload)": "https://example/v1/projects/p/vaults/v/versions/1:access",
		"log entries list (content)":  "https://logging.googleapis.com/v2/entries:list",
		"log entries tail (content)":  "https://logging.googleapis.com/v2/entries:tail",
	}
	for name, url := range flagged {
		src := "package p\nfunc run() { u := " + strconv.Quote(url) + "; _ = u }\n"
		if got := checkSource(token.NewFileSet(), "f.go", src); len(got) == 0 {
			t.Errorf("%s: path gate did not flag %q", name, url)
		}
	}

	// The same endpoints read for metadata (no content/payload fragment) must not be
	// flagged: alt=media absent returns object metadata, and a versions list has no
	// :access. This is the precision that keeps the gate signal, not noise.
	clean := map[string]string{
		"object metadata (no alt=media)": "https://storage.googleapis.com/storage/v1/b/bkt/o/obj",
		"bucket metadata":                "https://storage.googleapis.com/storage/v1/b/bkt",
		"versions list (no :access)":     "https://example/v1/projects/p/vaults/v/versions",
		"log sinks list (config)":        "https://logging.googleapis.com/v2/projects/p/sinks",
		"log buckets list (config)":      "https://logging.googleapis.com/v2/projects/p/locations/-/buckets",
	}
	for name, url := range clean {
		src := "package p\nfunc run() { u := " + strconv.Quote(url) + "; _ = u }\n"
		if got := checkSource(token.NewFileSet(), "f.go", src); len(got) != 0 {
			t.Errorf("%s: path gate wrongly flagged %q: %+v", name, url, got)
		}
	}
}

// TestForbiddenCoversOrganizationsWrites proves the gate bites the genuinely
// destructive AWS Organizations write operations (account creation and lifecycle,
// invitations, and policy attachment/modification) that the hierarchy collector, which
// reads Describe/List only, must never call, while the read operations it does call are
// not flagged.
func TestForbiddenCoversOrganizationsWrites(t *testing.T) {
	forbidden := []string{
		"CreateAccount", "CloseAccount", "MoveAccount", "RemoveAccountFromOrganization",
		"InviteAccountToOrganization", "CreateOrganizationalUnit", "DeleteOrganizationalUnit",
		"CreatePolicy", "DeletePolicy", "AttachPolicy", "DetachPolicy",
		"CreateOrganization", "DeleteOrganization", "LeaveOrganization",
	}
	for _, op := range forbidden {
		src := "package p\ntype c struct{}\nfunc (c) " + op + "() {}\nfunc run() { var x c; x." + op + "() }\n"
		got := checkSource(token.NewFileSet(), "f.go", src)
		if len(got) != 1 || got[0].Operation != op {
			t.Errorf("gate did not flag forbidden Organizations write %s: %+v", op, got)
		}
	}
	benign := []string{"DescribeOrganization", "ListRoots", "ListOrganizationalUnitsForParent", "ListAccountsForParent"}
	for _, op := range benign {
		src := "package p\ntype c struct{}\nfunc (c) " + op + "() {}\nfunc run() { var x c; x." + op + "() }\n"
		if got := checkSource(token.NewFileSet(), "f.go", src); len(got) != 0 {
			t.Errorf("gate wrongly flagged benign Organizations read %s: %+v", op, got)
		}
	}
}

// TestReadOnlyGatePassesCleanCode: a source that calls only benign operations is
// not flagged, so the gate is signal, not noise.
func TestReadOnlyGatePassesCleanCode(t *testing.T) {
	src := `package p
type c struct{}
func (c) DescribeInstances() {}
func (c) ListRoles() {}
func run() { var x c; x.DescribeInstances(); x.ListRoles() }
`
	if got := checkSource(token.NewFileSet(), "clean.go", src); len(got) != 0 {
		t.Fatalf("gate fired on benign calls: %+v", got)
	}
}

// TestForbiddenCoversAWSGetters proves the deny-list bites the AWS SDK content,
// secret-value, and key-material getters the resource collectors could otherwise
// call, and that benign metadata getters (the calls a storage collector actually
// makes) are not flagged, so the gate stays signal, not noise.
func TestForbiddenCoversAWSGetters(t *testing.T) {
	forbidden := []string{
		"GetObject", "SelectObjectContent", // object contents
		"GetSecretValue", "BatchGetSecretValue", // secret values
		"Decrypt", "GenerateDataKey", "GenerateDataKeyPair", // key material
		"GetPasswordData", "GetConsoleOutput", "GetConsoleScreenshot", // EC2 password and console content
		"GetLaunchTemplateData", "DescribeInstanceAttribute", "DescribeLaunchTemplateVersions", // EC2 user data
	}
	for _, op := range forbidden {
		src := "package p\ntype c struct{}\nfunc (c) " + op + "() {}\nfunc run() { var x c; x." + op + "() }\n"
		got := checkSource(token.NewFileSet(), "f.go", src)
		if len(got) != 1 || got[0].Operation != op {
			t.Errorf("gate did not flag forbidden getter %s: %+v", op, got)
		}
	}
	// The metadata-only calls the S3 and EC2 instance collectors actually make must
	// not be flagged.
	benign := []string{"ListBuckets", "GetBucketLocation", "GetPublicAccessBlock", "GetBucketPolicyStatus", "GetBucketEncryption", "GetBucketVersioning", "GetBucketTagging",
		"DescribeInstances", "GetInstanceProfile"}
	for _, op := range benign {
		src := "package p\ntype c struct{}\nfunc (c) " + op + "() {}\nfunc run() { var x c; x." + op + "() }\n"
		if got := checkSource(token.NewFileSet(), "f.go", src); len(got) != 0 {
			t.Errorf("gate wrongly flagged benign metadata call %s: %+v", op, got)
		}
	}
}

// TestProductionCodeIsReadOnly runs the gate over the real collector-adjacent
// code: the collection framework and the provider adapters. None may call a
// forbidden operation. This is the standing gate, not just a demonstration.
func TestProductionCodeIsReadOnly(t *testing.T) {
	for _, dir := range []string{".", "../../providers"} {
		v, err := CheckDir(dir)
		if err != nil {
			t.Fatalf("checking %s: %v", dir, err)
		}
		if len(v) != 0 {
			var lines []string
			for _, x := range v {
				lines = append(lines, x.File+": "+x.Operation+" ("+x.Reason+")")
			}
			t.Errorf("forbidden operations in %s:\n  %s", dir, strings.Join(lines, "\n  "))
		}
	}
}
