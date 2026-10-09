package collect

import (
	"context"
	"encoding/json"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const serviceAccountsCollectorID = "collector:kubernetes.serviceaccounts"

// ServiceAccountsCollector reads the cluster's service accounts: GET /api/v1/serviceaccounts
// across all namespaces, a read-only call verified against the Kubernetes API reference
// that returns object metadata, no token or secret. It emits one identity node per service
// account, keyed by its canonical principal "system:serviceaccount:<namespace>:<name>" (the
// exact string Kubernetes RBAC subjects and tokens use), with a contains edge from its
// namespace so the identity joins the cluster graph.
type ServiceAccountsCollector struct {
	lister
}

// NewServiceAccountsCollector builds the collector with the resolved read-only API client.
func NewServiceAccountsCollector(account string, api API, budget *collect.Budget) *ServiceAccountsCollector {
	return &ServiceAccountsCollector{lister{account: account, api: api, budget: budget}}
}

func (c *ServiceAccountsCollector) ID() string               { return serviceAccountsCollectorID }
func (c *ServiceAccountsCollector) Provider() model.Provider { return model.Kubernetes }

func serviceAccountsRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Kubernetes, Profile: permissions.Discovery, Permission: "list:serviceaccounts", By: serviceAccountsCollectorID},
	}
}

func init() {
	for _, r := range serviceAccountsRequirements() {
		permissions.Declare(r)
	}
}

func (c *ServiceAccountsCollector) Requirements() []permissions.Requirement {
	return serviceAccountsRequirements()
}

// Collect emits every service account as an identity node with a contains edge from its
// namespace, and records completeness.
func (c *ServiceAccountsCollector) Collect(ctx context.Context, sink collect.Sink) error {
	items, completeness := c.paginate(ctx, sink, "serviceaccounts", serviceAccountsCollectorID, "/api/v1/serviceaccounts", "serviceaccounts.list")
	for _, raw := range items {
		var sa struct {
			Metadata objectMeta `json:"metadata"`
		}
		if json.Unmarshal(raw, &sa) != nil || sa.Metadata.Name == "" || sa.Metadata.Namespace == "" {
			continue
		}
		said := serviceAccountID(sa.Metadata.Namespace, sa.Metadata.Name)
		_ = sink.Node(collect.Node{
			Type: model.NodeIdentity, NativeID: said, Name: sa.Metadata.Name,
			Attributes: attrs("kind", "ServiceAccount", "namespace", sa.Metadata.Namespace, "uid", sa.Metadata.UID, "cluster", c.account),
		})
		_ = sink.Link(collect.Link{SourceNativeID: namespaceID(sa.Metadata.Namespace), TargetNativeID: said, Kind: model.EdgeContains})
	}
	return sink.Complete(completeness)
}
