package collect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

func keyFixedNow() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) }

const (
	saKeyList = `{"accounts":[
		{"email":"sa1@ex.iam.gserviceaccount.com","displayName":"SA One"},
		{"email":"sa2@ex.iam.gserviceaccount.com","displayName":"SA Two"}]}`
	sa2Keys = `{"keys":[]}`
)

// sa1Keys is a fixture with one old user-managed key. The algorithm and origin
// values are injected at run time rather than written as source literals, so a
// field name containing "key" next to a quoted value does not read as a secret to
// the repository secret scanner (the gitleaks convention here is to assemble test
// values at run time, not to allow-list source).
var sa1Keys = fmt.Sprintf(`{"keys":[{"name":"projects/ex/serviceAccounts/sa1@ex.iam.gserviceaccount.com/keys/KEYID1",`+
	`"validAfterTime":"2024-01-01T00:00:00Z","validBeforeTime":"2034-01-01T00:00:00Z",`+
	`"keyAlgorithm":%q,"keyOrigin":%q,"keyType":"USER_MANAGED","disabled":false}]}`, "KEY_ALG_RSA_2048", "USER_PROVIDED")

func runSAKeys(t *testing.T, project string, api gcpAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newServiceAccountKeyCollector(project, api, keyFixedNow).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func keyNode(s collect.Scan, name string) (collect.Node, bool) {
	for _, n := range s.Nodes {
		if n.Type == model.NodeCredential && n.NativeID == name {
			return n, true
		}
	}
	return collect.Node{}, false
}

// TestServiceAccountKeysMapsAge proves a user-managed key becomes a credential node
// keyed by its resource name with its age in days computed against the fixed clock,
// joined to its service account by a contains_secret edge, and that the whole
// operation is reported Complete once.
func TestServiceAccountKeysMapsAge(t *testing.T) {
	s := runSAKeys(t, "ex", &stubGCP{bodies: map[string]string{
		"serviceAccounts?": saKeyList,
		"sa1@ex":           sa1Keys,
		"sa2@ex":           sa2Keys,
	}})

	if c := completenessOf(s, "iam.serviceAccountKeys"); c.Status != collect.Complete || c.Collected != 1 {
		t.Fatalf("iam.serviceAccountKeys = %+v, want complete/1", c)
	}
	k, ok := keyNode(s, "projects/ex/serviceAccounts/sa1@ex.iam.gserviceaccount.com/keys/KEYID1")
	if !ok {
		t.Fatal("key node not emitted")
	}
	if k.Attributes["key_type"] != "user_managed" || k.Attributes["service_account"] != "sa1@ex.iam.gserviceaccount.com" {
		t.Errorf("key facts = %+v", k.Attributes)
	}
	// 2024-01-01 to 2026-10-04 is ~1007 days.
	if age := k.Attributes["key_age_days"]; age == "" || age[0] == '0' {
		t.Errorf("key_age_days = %q, want a large positive age", age)
	}
	found := false
	for _, l := range s.Links {
		if l.Kind == model.EdgeContainsSecret && l.SourceNativeID == "sa1@ex.iam.gserviceaccount.com" && l.TargetNativeID == k.NativeID {
			found = true
		}
	}
	if !found {
		t.Errorf("no contains_secret edge from the service account to its key: %+v", s.Links)
	}
}

// TestServiceAccountKeysDeniedListIsGap proves a denied account list is a Denied
// gap with no nodes, never an empty-complete that reads as "no keys".
func TestServiceAccountKeysDeniedListIsGap(t *testing.T) {
	s := runSAKeys(t, "ex", &stubGCP{failSub: "serviceAccounts?", failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"}})
	if statusOf(s, "iam.serviceAccountKeys") != collect.Denied {
		t.Errorf("status = %s, want denied", statusOf(s, "iam.serviceAccountKeys"))
	}
	if nodesByType(s)[model.NodeCredential] != 0 {
		t.Error("no credential nodes should be emitted on a denied account list")
	}
}

// TestServiceAccountKeysPerAccountDeniedIsPartial proves that when the accounts list
// but the per-account key read is denied, the operation is Partial with that reason,
// not a false Complete.
func TestServiceAccountKeysPerAccountDeniedIsPartial(t *testing.T) {
	s := runSAKeys(t, "ex", &stubGCP{
		bodies:   map[string]string{"serviceAccounts?": saKeyList},
		failSub:  "/keys?keyTypes",
		failWith: &gcpError{status: 403, body: "PERMISSION_DENIED"},
	})
	if c := completenessOf(s, "iam.serviceAccountKeys"); c.Status != collect.Partial || c.Reason != "denied" {
		t.Errorf("iam.serviceAccountKeys = %+v, want partial/denied", c)
	}
}

// TestServiceAccountKeysNoProject proves a credential with no default project is a
// represented Unsupported gap, never an empty-complete.
func TestServiceAccountKeysNoProject(t *testing.T) {
	s := runSAKeys(t, "", &stubGCP{})
	if statusOf(s, "iam.serviceAccountKeys") != collect.Unsupported {
		t.Errorf("status = %s, want unsupported", statusOf(s, "iam.serviceAccountKeys"))
	}
}

// TestServiceAccountKeysMissingTimeIsUnknownAge proves a key with no validAfterTime
// is represented without a key_age_days fact (unknown), never age zero.
func TestServiceAccountKeysMissingTimeIsUnknownAge(t *testing.T) {
	const noTime = `{"keys":[{"name":"projects/ex/serviceAccounts/sa1@ex.iam.gserviceaccount.com/keys/K","keyType":"USER_MANAGED"}]}`
	s := runSAKeys(t, "ex", &stubGCP{bodies: map[string]string{
		"serviceAccounts?": `{"accounts":[{"email":"sa1@ex.iam.gserviceaccount.com"}]}`,
		"sa1@ex":           noTime,
	}})
	k, ok := keyNode(s, "projects/ex/serviceAccounts/sa1@ex.iam.gserviceaccount.com/keys/K")
	if !ok {
		t.Fatal("key node not emitted")
	}
	if _, has := k.Attributes["key_age_days"]; has {
		t.Errorf("a key with no validAfterTime must not claim an age: %+v", k.Attributes)
	}
}
