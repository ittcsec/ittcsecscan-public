//go:build live

package k8s

import (
	"context"
	"os"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/auth"
	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

// TestLiveKubernetes runs the real read-only Kubernetes path against the cluster the pod
// is running in. It is maintainer-run (the live build tag) and only meaningful in-cluster; it
// skips when the in-cluster service account env is absent. It confirms identity resolution
// and that the collectors emit cluster/namespace/identity/role nodes without erroring.
func TestLiveKubernetes(t *testing.T) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		t.Skip("not running in a cluster; set KUBERNETES_SERVICE_HOST to run the live Kubernetes test")
	}
	ctx := context.Background()
	src := NewSource(os.LookupEnv)

	id, err := src.adapter.Resolve(ctx, model.Kubernetes, auth.Discovery)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if id.Account == "" {
		t.Fatal("resolved identity has no cluster URL")
	}
	t.Logf("resolved cluster=%s principal=%s", id.Account, id.Principal)

	account, collectors, err := src.Collectors(ctx, collect.NewBudget(500))
	if err != nil {
		t.Fatalf("collectors: %v", err)
	}
	var scan collect.Scan
	if err := collect.Run(ctx, collectors, &scan); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, c := range scan.Completeness {
		if c.Status == collect.Errored {
			t.Errorf("collector errored: %+v", c)
		}
	}
	counts := map[model.NodeType]int{}
	for _, n := range scan.Nodes {
		counts[n.Type]++
	}
	assumes := 0
	for _, l := range scan.Links {
		if l.Kind == model.EdgeAssumes {
			assumes++
		}
	}
	t.Logf("cluster=%s namespaces=%d identities=%d roles=%d assumes-edges=%d",
		account, counts[model.NodeNamespace], counts[model.NodeIdentity], counts[model.NodeRole], assumes)
}
