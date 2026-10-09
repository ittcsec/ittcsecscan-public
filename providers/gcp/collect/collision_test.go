package collect

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/ingest"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

// TestServiceAccountCollisionResolvesEndToEnd proves the entity-dedup fix in the
// real scenario it was built for, not only the isolated dedup unit test: the
// service-account collector and the IAM policy collector both report the same
// service account, and the merged scan ingests as one entity with the grant edge
// resolving to it. Without the dedup this ingest fails on the unique stable-id
// index, so a clean ingest with the edge kept is the proof the collision is
// resolved through the real collectors and the real store.
func TestServiceAccountCollisionResolvesEndToEnd(t *testing.T) {
	const saEmail = "sa@p.iam.gserviceaccount.com"
	saAPI := &stubGCP{bodies: map[string]string{
		"serviceAccounts": `{"accounts":[{"email":"` + saEmail + `","displayName":"CI Runner"}]}`,
	}}
	policyAPI := &stubPolicy{body: `{"bindings":[{"role":"roles/editor","members":["serviceAccount:` + saEmail + `"]}]}`}

	var scan collect.Scan
	cols := []collect.Collector{
		newIdentityCollector("proj", saAPI),   // emits the SA (native id: the email)
		newPolicyCollector("proj", policyAPI), // emits the same SA as a member (same email)
	}
	if err := collect.Run(context.Background(), cols, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}

	now := time.Now().UTC()
	in := ingest.ToStore(scan, ingest.Meta{ToolVersion: "v", Provider: model.GCP, Started: now, Completed: now})

	res, err := newTenant(t).Ingest(context.Background(), in)
	if err != nil {
		t.Fatalf("ingest failed, so the service-account collision was not resolved: %v", err)
	}
	if res.DroppedEdges != 0 {
		t.Errorf("dropped edges = %d, want 0 (the grant edge resolves to the merged service account)", res.DroppedEdges)
	}
}

// newTenant creates a real, empty tenant in a temp data directory with a
// throwaway master key, so a test can exercise the full ingest path.
func newTenant(t *testing.T) *store.Tenant {
	t.Helper()
	root := t.TempDir()
	keyFile := filepath.Join(root, "master.key")
	const pass = "collision-test-passphrase"
	if err := store.InitMasterKey(keyFile, 1, []byte(pass)); err != nil {
		t.Fatalf("init master key: %v", err)
	}
	keys := store.NewFileMasterKeys(keyFile, func() ([]byte, error) { return []byte(pass), nil })
	s, err := store.New(store.Options{DataDir: filepath.Join(root, "data"), Keys: keys})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	id, err := s.Create(ctx)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tn, release, err := s.Acquire(ctx, id)
	if err != nil {
		t.Fatalf("acquire tenant: %v", err)
	}
	t.Cleanup(release)
	return tn
}
