package collect

import (
	"context"
	"encoding/json"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/permissions"
)

const rbacCollectorID = "collector:kubernetes.rbac"

const rbacGroup = "/apis/rbac.authorization.k8s.io/v1"

// RBACCollector reads the cluster's role-based access control graph: cluster roles and
// roles (as role nodes) and cluster role bindings and role bindings (as assumes edges
// from each subject to the role it is bound to). All four are read-only list calls
// verified against the Kubernetes RBAC API reference that return object metadata, no
// secret. A subject (service account, user, or group) that is bound to a role assumes
// that role's permissions, the same "principal assumes role/policy" edge the cloud
// identity collectors emit, so the Kubernetes authorization graph joins the shared model.
type RBACCollector struct {
	lister
}

// NewRBACCollector builds the collector with the resolved read-only API client.
func NewRBACCollector(account string, api API, budget *collect.Budget) *RBACCollector {
	return &RBACCollector{lister{account: account, api: api, budget: budget}}
}

func (c *RBACCollector) ID() string               { return rbacCollectorID }
func (c *RBACCollector) Provider() model.Provider { return model.Kubernetes }

func rbacRequirements() []permissions.Requirement {
	p := func(perm string) permissions.Requirement {
		return permissions.Requirement{Provider: model.Kubernetes, Profile: permissions.Discovery, Permission: perm, By: rbacCollectorID}
	}
	return []permissions.Requirement{
		p("list:roles.rbac.authorization.k8s.io"),
		p("list:rolebindings.rbac.authorization.k8s.io"),
		p("list:clusterroles.rbac.authorization.k8s.io"),
		p("list:clusterrolebindings.rbac.authorization.k8s.io"),
	}
}

func init() {
	for _, r := range rbacRequirements() {
		permissions.Declare(r)
	}
}

func (c *RBACCollector) Requirements() []permissions.Requirement { return rbacRequirements() }

type roleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Collect reads the four RBAC resource types and emits role nodes and subject-to-role
// assumes edges. Each resource type records its own completeness (each is its own read).
func (c *RBACCollector) Collect(ctx context.Context, sink collect.Sink) error {
	c.collectRoles(ctx, sink, "clusterroles", rbacGroup+"/clusterroles", true)
	c.collectRoles(ctx, sink, "roles", rbacGroup+"/roles", false)
	c.collectBindings(ctx, sink, "clusterrolebindings", rbacGroup+"/clusterrolebindings")
	c.collectBindings(ctx, sink, "rolebindings", rbacGroup+"/rolebindings")
	return nil
}

// collectRoles emits a role node per (cluster) role. clusterScoped selects the native-id
// form: a ClusterRole is cluster-wide, a Role is namespaced.
func (c *RBACCollector) collectRoles(ctx context.Context, sink collect.Sink, service, path string, clusterScoped bool) {
	items, completeness := c.paginate(ctx, sink, service, rbacCollectorID, path, service+".list")
	for _, raw := range items {
		var r struct {
			Metadata objectMeta `json:"metadata"`
		}
		if json.Unmarshal(raw, &r) != nil || r.Metadata.Name == "" {
			continue
		}
		var id, kind string
		if clusterScoped {
			id, kind = clusterRoleID(r.Metadata.Name), "ClusterRole"
		} else {
			if r.Metadata.Namespace == "" {
				continue
			}
			id, kind = roleID(r.Metadata.Namespace, r.Metadata.Name), "Role"
		}
		_ = sink.Node(collect.Node{
			Type: model.NodeRole, NativeID: id, Name: r.Metadata.Name,
			Attributes: attrs("kind", kind, "namespace", r.Metadata.Namespace, "uid", r.Metadata.UID, "cluster", c.account),
		})
	}
	_ = sink.Complete(completeness)
}

// collectBindings emits, for each binding, an assumes edge from every subject to the role
// the binding references, plus the subject node so the edge resolves.
func (c *RBACCollector) collectBindings(ctx context.Context, sink collect.Sink, service, path string) {
	items, completeness := c.paginate(ctx, sink, service, rbacCollectorID, path, service+".list")
	for _, raw := range items {
		var b struct {
			Metadata objectMeta `json:"metadata"`
			RoleRef  roleRef    `json:"roleRef"`
			Subjects []subject  `json:"subjects"`
		}
		if json.Unmarshal(raw, &b) != nil || b.RoleRef.Name == "" {
			continue
		}
		target := roleRefID(b.RoleRef, b.Metadata.Namespace)
		if target == "" {
			continue
		}
		for _, s := range b.Subjects {
			srcID, node, ok := subjectNode(s, b.Metadata.Namespace, c.account)
			if !ok {
				continue
			}
			_ = sink.Node(node)
			_ = sink.Link(collect.Link{SourceNativeID: srcID, TargetNativeID: target, Kind: model.EdgeAssumes})
		}
	}
	_ = sink.Complete(completeness)
}

// roleRefID resolves a binding's roleRef to the native id of the role node. A ClusterRole
// ref is cluster-wide; a Role ref is in the binding's own namespace. bindingNS is empty
// for a ClusterRoleBinding.
func roleRefID(ref roleRef, bindingNS string) string {
	switch ref.Kind {
	case "ClusterRole":
		return clusterRoleID(ref.Name)
	case "Role":
		if bindingNS == "" {
			return ""
		}
		return roleID(bindingNS, ref.Name)
	default:
		return ""
	}
}

// subjectNode resolves a binding subject to its native id and node. A ServiceAccount is an
// identity keyed by its canonical principal (defaulting a missing subject namespace to the
// binding's), a User is an identity, a Group is a group. bindingNS is the binding's
// namespace (empty for a ClusterRoleBinding).
func subjectNode(s subject, bindingNS, account string) (string, collect.Node, bool) {
	switch s.Kind {
	case "ServiceAccount":
		ns := s.Namespace
		if ns == "" {
			ns = bindingNS
		}
		if ns == "" || s.Name == "" {
			return "", collect.Node{}, false
		}
		id := serviceAccountID(ns, s.Name)
		return id, collect.Node{Type: model.NodeIdentity, NativeID: id, Name: s.Name, Attributes: attrs("kind", "ServiceAccount", "namespace", ns, "cluster", account)}, true
	case "User":
		if s.Name == "" {
			return "", collect.Node{}, false
		}
		id := "user:" + s.Name
		return id, collect.Node{Type: model.NodeIdentity, NativeID: id, Name: s.Name, Attributes: attrs("kind", "User", "cluster", account)}, true
	case "Group":
		if s.Name == "" {
			return "", collect.Node{}, false
		}
		id := "group:" + s.Name
		return id, collect.Node{Type: model.NodeGroup, NativeID: id, Name: s.Name, Attributes: attrs("kind", "Group", "cluster", account)}, true
	default:
		return "", collect.Node{}, false
	}
}
