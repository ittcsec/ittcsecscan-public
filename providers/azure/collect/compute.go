package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/redact"
	"github.com/ittcsec/ittcsecscan/permissions"
)

// computeCollectorID is the stable id this collector is credited with.
const computeCollectorID = "collector:azure.compute.virtualmachines"

// computeAPIVersion is the doc-verified Compute Resource Provider API version
// (2026-09-21). The Virtual Machines List All operation returns each VM's full
// properties and its managed-identity block, and no secret value.
const computeAPIVersion = "2026-04-01"

// ComputeCollector reads the tenant's Azure virtual machines and their
// security-relevant configuration, the Azure counterpart of the AWS EC2 instances
// and GCP GCE instances collectors. VMs live on the Resource Manager plane and are
// subscription-scoped, so the collector enumerates the accessible subscriptions and
// lists each one's VMs in a single paginated call (the list carries the full
// properties and identity, so there is no per-VM fan-out).
//
// The headline fact is the run-as edge: a VM can act as its managed identity, so the
// collector emits an assumes edge from the VM to each attached managed identity
// (system- and user-assigned), keyed by the identity's principal id so it dedups
// with the Entra service-principal nodes and the RBAC principal nodes. That closes
// the path from a VM through its identity to the roles it holds. Per ADR-0019 §3 the
// collector emits nodes, attributes, and that run-as edge only; disk encryption sets
// and network interfaces are recorded as id facts for the encryption and networking
// collectors to join. The read was verified against the Azure Compute REST reference
// (2026-09-21): a read-only GET, paginated by nextLink, returning no secret value.
type ComputeCollector struct {
	tenantID string
	api      armAPI
	budget   *collect.Budget // the scan's shared call cap; nil is unlimited
}

// NewComputeCollector builds the collector with an ARM client that mints a
// management-scoped token from the adapter's resolved credential (ADR-0018 §3).
func NewComputeCollector(tenantID string, cred azcore.TokenCredential, budget *collect.Budget) *ComputeCollector {
	return &ComputeCollector{tenantID: tenantID, api: &armClient{cred: cred, http: sharedHTTPClient}, budget: budget}
}

// newComputeCollector is the injectable constructor tests use with a stub API. It
// has no budget (unlimited); a test that needs one sets the field.
func newComputeCollector(tenantID string, api armAPI) *ComputeCollector {
	return &ComputeCollector{tenantID: tenantID, api: api}
}

func (c *ComputeCollector) ID() string               { return computeCollectorID }
func (c *ComputeCollector) Provider() model.Provider { return model.Azure }

func computeRequirements() []permissions.Requirement {
	return []permissions.Requirement{
		{Provider: model.Azure, Profile: permissions.Discovery, Permission: "Microsoft.Compute/virtualMachines/read", By: computeCollectorID},
	}
}

func init() {
	for _, r := range computeRequirements() {
		permissions.Declare(r)
	}
}

// Requirements declares the read-only permissions the collector needs.
func (c *ComputeCollector) Requirements() []permissions.Requirement { return computeRequirements() }

// Collect enumerates the accessible subscriptions and, for each, lists its virtual
// machines and maps each to a compute node with its run-as edge. Two completeness
// records are produced: compute.subscriptions and compute.virtualMachines (per
// subscription). Compute is a global management-plane read, so there is one region:
// "global"; each VM's Azure location is recorded as an attribute.
func (c *ComputeCollector) Collect(ctx context.Context, sink collect.Sink) error {
	tenantScope := collect.Scope{Account: c.tenantID}
	var subs []subscription
	err := c.pageThrough(ctx, sink, "compute.subscriptions", tenantScope, subscriptionsAPIVersion,
		fmt.Sprintf("%s/subscriptions?api-version=%s", armBaseURL, subscriptionsAPIVersion),
		func(raw json.RawMessage) (int, error) {
			var page []subscription
			if err := json.Unmarshal(raw, &page); err != nil {
				return 0, err
			}
			subs = append(subs, page...)
			return len(page), nil
		})
	if err != nil {
		return err
	}

	for _, sub := range subs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sub.SubscriptionID == "" {
			continue
		}
		_ = sink.Node(collect.Node{Type: model.NodeSubscription, NativeID: sub.SubscriptionID, Name: sub.DisplayName,
			Attributes: attrs("state", sub.State)})
		scope := collect.Scope{Account: c.tenantID, Resource: sub.SubscriptionID}
		_ = c.pageThrough(ctx, sink, "compute.virtualMachines", scope, computeAPIVersion,
			fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=%s", armBaseURL, sub.SubscriptionID, computeAPIVersion),
			func(raw json.RawMessage) (int, error) {
				var page []virtualMachine
				if err := json.Unmarshal(raw, &page); err != nil {
					return 0, err
				}
				for _, vm := range page {
					c.mapVM(sink, vm)
				}
				return len(page), nil
			})
	}
	return nil
}

// mapVM emits one compute node per VM (keyed by its ARM resource id), records its
// security posture as facts, and emits the run-as edge to each attached managed
// identity.
func (c *ComputeCollector) mapVM(sink collect.Sink, vm virtualMachine) {
	if vm.ID == "" {
		return
	}
	p := vm.Properties
	a := map[string]string{
		"azure_type":         "virtual_machine",
		"location":           vm.Location,
		"vm_size":            p.HardwareProfile.VMSize,
		"provisioning_state": p.ProvisioningState,
		"vm_id":              p.VMID,
		"zones":              strings.Join(vm.Zones, ","),
	}
	if o := p.OSProfile; o != nil {
		a["admin_username"] = o.AdminUsername
		if l := o.LinuxConfiguration; l != nil {
			a["disable_password_authentication"] = boolAttr(l.DisablePasswordAuthentication)
		}
	}
	if s := p.StorageProfile; s != nil && s.OSDisk != nil && s.OSDisk.ManagedDisk != nil {
		a["os_disk_storage_type"] = s.OSDisk.ManagedDisk.StorageAccountType
		if des := s.OSDisk.ManagedDisk.DiskEncryptionSet; des != nil {
			// The customer-managed disk-encryption-set reference, an id fact for a
			// future encryption collector to join.
			a["os_disk_encryption_set"] = des.ID
		}
	}
	if s := p.SecurityProfile; s != nil {
		a["security_type"] = s.SecurityType
		a["encryption_at_host"] = boolAttr(s.EncryptionAtHost)
		if u := s.UefiSettings; u != nil {
			a["secure_boot_enabled"] = boolAttr(u.SecureBootEnabled)
			a["vtpm_enabled"] = boolAttr(u.VTpmEnabled)
		}
	}
	if n := p.NetworkProfile; n != nil {
		var ids []string
		for _, ni := range n.NetworkInterfaces {
			if ni.ID != "" {
				ids = append(ids, ni.ID)
			}
		}
		sort.Strings(ids)
		a["network_interface_ids"] = strings.Join(ids, ",")
	}
	if vm.Identity != nil {
		a["identity_type"] = vm.Identity.Type
	}
	for k, v := range vm.Tags {
		if k != "" {
			a["tag:"+k] = v
		}
	}
	_ = sink.Node(collect.Node{Type: model.NodeCompute, NativeID: vm.ID, Name: vm.Name, Attributes: pruneEmptyAzure(a)})

	c.runAsEdges(sink, vm)
}

// runAsEdges emits the assumes edge from a VM to each managed identity it can act
// as: the system-assigned identity (identity.principalId) and each user-assigned
// identity. The managed-identity node is keyed by its principal id (its Entra object
// id), so it dedups with the Entra and RBAC principal nodes; a minimal node is
// emitted so the edge never dangles.
func (c *ComputeCollector) runAsEdges(sink collect.Sink, vm virtualMachine) {
	id := vm.Identity
	if id == nil {
		return
	}
	emit := func(principalID string) {
		if principalID == "" {
			return
		}
		_ = sink.Node(collect.Node{Type: model.NodeWorkload, NativeID: principalID, Attributes: attrs("principal_type", "ManagedIdentity")})
		_ = sink.Link(collect.Link{SourceNativeID: vm.ID, TargetNativeID: principalID, Kind: model.EdgeAssumes})
	}
	emit(id.PrincipalID)
	for _, ua := range id.UserAssignedIdentities {
		emit(ua.PrincipalID)
	}
}

// virtualMachine is the subset of the VirtualMachine resource the collector reads
// (verified against the Compute REST reference, 2026-09-21).
type virtualMachine struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Location string            `json:"location"`
	Zones    []string          `json:"zones"`
	Tags     map[string]string `json:"tags"`
	Identity *struct {
		Type                   string `json:"type"`
		PrincipalID            string `json:"principalId"`
		UserAssignedIdentities map[string]struct {
			PrincipalID string `json:"principalId"`
		} `json:"userAssignedIdentities"`
	} `json:"identity"`
	Properties struct {
		VMID              string `json:"vmId"`
		ProvisioningState string `json:"provisioningState"`
		HardwareProfile   struct {
			VMSize string `json:"vmSize"`
		} `json:"hardwareProfile"`
		OSProfile *struct {
			AdminUsername      string `json:"adminUsername"`
			LinuxConfiguration *struct {
				DisablePasswordAuthentication *bool `json:"disablePasswordAuthentication"`
			} `json:"linuxConfiguration"`
		} `json:"osProfile"`
		StorageProfile *struct {
			OSDisk *struct {
				ManagedDisk *struct {
					StorageAccountType string `json:"storageAccountType"`
					DiskEncryptionSet  *struct {
						ID string `json:"id"`
					} `json:"diskEncryptionSet"`
				} `json:"managedDisk"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		NetworkProfile *struct {
			NetworkInterfaces []struct {
				ID string `json:"id"`
			} `json:"networkInterfaces"`
		} `json:"networkProfile"`
		SecurityProfile *struct {
			SecurityType     string `json:"securityType"`
			EncryptionAtHost *bool  `json:"encryptionAtHost"`
			UefiSettings     *struct {
				SecureBootEnabled *bool `json:"secureBootEnabled"`
				VTpmEnabled       *bool `json:"vTpmEnabled"`
			} `json:"uefiSettings"`
		} `json:"securityProfile"`
	} `json:"properties"`
}

// pageThrough fetches every page of an ARM list starting at firstURL, spending
// budget per page and recording evidence and completeness for service at scope. A
// denied or throttled read is a represented gap (returns nil); an unexpected error
// is surfaced; a page is never reported Complete on a failure.
func (c *ComputeCollector) pageThrough(ctx context.Context, sink collect.Sink, service string, scope collect.Scope, apiVersion, firstURL string, handle func(json.RawMessage) (int, error)) error {
	url := firstURL
	count := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			_ = sink.Complete(computeGap(service, scope, collect.Partial, count, "page limit reached"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			_ = sink.Complete(computeGap(service, scope, collect.Partial, count, "cancelled"))
			return err
		}
		if !c.budget.Spend() {
			_ = sink.Complete(computeGap(service, scope, collect.Partial, count, "budget exhausted"))
			return nil
		}
		body, err := c.api.get(ctx, url)
		if err != nil {
			_ = sink.Complete(c.completeness(service, scope, count, err))
			if isDenied(err) || isThrottle(err) {
				return nil
			}
			return err
		}
		_ = sink.Evidence(c.evidence(service, apiVersion, scope, body))
		var list armList
		if err := json.Unmarshal(body, &list); err != nil {
			_ = sink.Complete(computeGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: decoding page: %w", service, err)
		}
		n, err := handle(list.Value)
		if err != nil {
			_ = sink.Complete(computeGap(service, scope, collect.Errored, count, redact.String(err.Error())))
			return fmt.Errorf("%s: mapping page: %w", service, err)
		}
		count += n
		if list.NextLink == "" {
			_ = sink.Complete(computeGap(service, scope, collect.Complete, count, ""))
			return nil
		}
		url = list.NextLink
	}
}

func (c *ComputeCollector) evidence(service, apiVersion string, scope collect.Scope, body []byte) collect.Envelope {
	return collect.Envelope{
		Provider: model.Azure, Service: "compute", Operation: service, Region: collect.Global,
		Scope:      scope,
		Response:   json.RawMessage(redact.String(string(body))),
		Provenance: collect.Provenance{APIVersion: apiVersion, Collector: computeCollectorID},
	}
}

func (c *ComputeCollector) completeness(service string, scope collect.Scope, collected int, err error) collect.Completeness {
	status := collect.Errored
	switch {
	case isDenied(err):
		status = collect.Denied
	case isThrottle(err):
		status = collect.Partial
	}
	return computeGap(service, scope, status, collected, redact.String(err.Error()))
}

func computeGap(service string, scope collect.Scope, status collect.Status, collected int, reason string) collect.Completeness {
	return collect.Completeness{Service: service, Region: collect.Global, Scope: scope, Status: status, Collected: collected, Reason: reason}
}
