package collect

import (
	"context"
	"encoding/json"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const namespacesCollectorID = "collector:kubernetes.namespaces"

// NamespacesCollector reads the cluster's namespaces: GET /api/v1/namespaces, a read-only
// call verified against the Kubernetes API reference that returns object metadata, no
// secret or content. It emits the cluster node once (keyed by the API server URL) and one
// namespace node per namespace, with a contains edge from the cluster, so later collectors
// (service accounts, RBAC) join their objects into the same cluster graph.
type NamespacesCollector struct {
	lister
}

// NewNamespacesCollector builds the collector with the resolved read-only API client.
func NewNamespacesCollector(account string, api API, budget *collect.Budget) *NamespacesCollector {
	return &NamespacesCollector{lister{account: account, api: api, budget: budget}}
}

func (c *NamespacesCollector) ID() string               { return namespacesCollectorID }
func (c *NamespacesCollector) Provider() model.Provider { return model.Kubernetes }

func namespacesRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Kubernetes, Profile: permissions.Discovery, Permission: "list:namespaces", By: namespacesCollectorID},
	}
}

func init() {
	for _, r := range namespacesRequirements() {
		permissions.Declare(r)
	}
}

func (c *NamespacesCollector) Requirements() []permissions.Requirement {
	return namespacesRequirements()
}

// Collect emits the cluster node and every namespace with a contains edge from the
// cluster, and records completeness.
func (c *NamespacesCollector) Collect(ctx context.Context, sink collect.Sink) error {
	// The cluster node is emitted unconditionally: even if the namespace listing is
	// denied, the cluster (the authenticated endpoint) is a real, represented node.
	_ = sink.Node(collect.Node{Type: model.NodeCluster, NativeID: c.account, Name: c.account, Attributes: attrs("api_server", c.account)})

	items, completeness := c.paginate(ctx, sink, "namespaces", namespacesCollectorID, "/api/v1/namespaces", "namespaces.list")
	for _, raw := range items {
		var ns struct {
			Metadata objectMeta `json:"metadata"`
		}
		if json.Unmarshal(raw, &ns) != nil || ns.Metadata.Name == "" {
			continue
		}
		nsID := namespaceID(ns.Metadata.Name)
		_ = sink.Node(collect.Node{Type: model.NodeNamespace, NativeID: nsID, Name: ns.Metadata.Name, Attributes: attrs("uid", ns.Metadata.UID, "cluster", c.account)})
		_ = sink.Link(collect.Link{SourceNativeID: c.account, TargetNativeID: nsID, Kind: model.EdgeContains})
	}
	return sink.Complete(completeness)
}
