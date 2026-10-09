package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/collect"
	"github.com/ittcsec/ittcsecscan/internal/model"
)

const vmID = "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/web-vm"

// oneVM is a virtualMachines.list page: one Linux VM with a system-assigned and a
// user-assigned managed identity, SSH-key-only auth, Trusted Launch security, a
// CMK disk-encryption set, and a network interface reference.
const oneVM = `{"value":[
	{"id":"` + vmID + `","name":"web-vm","location":"eastus","zones":["1"],"tags":{"env":"prod"},
	 "identity":{"type":"SystemAssigned, UserAssigned","principalId":"sys-principal","userAssignedIdentities":{"/subscriptions/sub-1/.../uai1":{"principalId":"uai-principal","clientId":"c1"}}},
	 "properties":{
	   "vmId":"vm-guid","provisioningState":"Succeeded",
	   "hardwareProfile":{"vmSize":"Standard_D2s_v5"},
	   "osProfile":{"adminUsername":"azureuser","linuxConfiguration":{"disablePasswordAuthentication":true}},
	   "storageProfile":{"osDisk":{"managedDisk":{"storageAccountType":"Premium_LRS","diskEncryptionSet":{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/diskEncryptionSets/des1"}}}},
	   "networkProfile":{"networkInterfaces":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/web-nic"}]},
	   "securityProfile":{"securityType":"TrustedLaunch","encryptionAtHost":true,"uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}}}}
]}`

func runCompute(t *testing.T, api armAPI) collect.Scan {
	t.Helper()
	var s collect.Scan
	if err := newComputeCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return s
}

func computeStub() *stubARM {
	return &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"virtualMachines": oneVM,
	}}
}

// TestComputeMapsVM proves a VM becomes a compute node keyed by its ARM resource id
// with its security posture and cross-references recorded as facts.
func TestComputeMapsVM(t *testing.T) {
	s := runCompute(t, computeStub())
	n, ok := nodeNamed(s, model.NodeCompute, vmID)
	if !ok {
		t.Fatal("web-vm not keyed by its ARM resource id")
	}
	for k, v := range map[string]string{
		"azure_type": "virtual_machine", "location": "eastus", "vm_size": "Standard_D2s_v5",
		"provisioning_state": "Succeeded", "zones": "1", "admin_username": "azureuser",
		"disable_password_authentication": "true", "os_disk_storage_type": "Premium_LRS",
		"os_disk_encryption_set": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/diskEncryptionSets/des1",
		"security_type":          "TrustedLaunch", "encryption_at_host": "true",
		"secure_boot_enabled": "true", "vtpm_enabled": "true",
		"network_interface_ids": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/web-nic",
		"identity_type":         "SystemAssigned, UserAssigned", "tag:env": "prod",
	} {
		if n.Attributes[k] != v {
			t.Errorf("web-vm %s = %q, want %q", k, n.Attributes[k], v)
		}
	}
	// No synthesized verdict.
	for _, forbidden := range []string{"is_public", "exposed", "compliant"} {
		if _, ok := n.Attributes[forbidden]; ok {
			t.Errorf("collector must not synthesize a %q verdict", forbidden)
		}
	}
	if c := completenessOf(s, "compute.virtualMachines"); c.Status != collect.Complete || c.Collected != 1 {
		t.Errorf("compute.virtualMachines = %+v, want complete/1", c)
	}
}

// TestComputeRunAsEdges proves the VM-to-managed-identity run-as edges: one for the
// system-assigned identity and one per user-assigned identity, each keyed by the
// identity's principal id (so it dedups with the Entra and RBAC principal nodes).
func TestComputeRunAsEdges(t *testing.T) {
	s := runCompute(t, computeStub())

	targets := map[string]bool{}
	for _, l := range s.Links {
		if l.Kind != model.EdgeAssumes {
			t.Errorf("edge kind = %s, want assumes", l.Kind)
		}
		if l.SourceNativeID == vmID {
			targets[l.TargetNativeID] = true
		}
	}
	for _, want := range []string{"sys-principal", "uai-principal"} {
		if !targets[want] {
			t.Errorf("missing run-as edge web-vm -> %s", want)
		}
		if _, ok := nodeNamed(s, model.NodeWorkload, want); !ok {
			t.Errorf("managed identity %s not emitted as a workload node keyed by principal id", want)
		}
	}
	if len(targets) != 2 {
		t.Errorf("run-as edge targets = %d, want 2 (system + user assigned)", len(targets))
	}
}

// TestComputeNoIdentityNoEdge proves a VM with no managed identity produces no run-as
// edge.
func TestComputeNoIdentityNoEdge(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"virtualMachines": `{"value":[{"id":"` + vmID + `","name":"web-vm","properties":{"vmId":"g"}}]}`,
	}}
	s := runCompute(t, api)
	if _, ok := nodeNamed(s, model.NodeCompute, vmID); !ok {
		t.Fatal("VM not emitted")
	}
	if len(s.Links) != 0 {
		t.Errorf("run-as edges = %d, want 0 (no managed identity)", len(s.Links))
	}
}

// TestComputeVMsDeniedIsGap proves a denied virtualMachines read is a Denied gap
// (never a pass) that does not fail the run.
func TestComputeVMsDeniedIsGap(t *testing.T) {
	api := computeStub()
	api.failSub = "virtualMachines"
	api.failWith = &azureError{status: 403, body: "AuthorizationFailed"}
	var s collect.Scan
	if err := newComputeCollector("tenant-1", api).Collect(context.Background(), &s); err != nil {
		t.Fatalf("a denied VM read must not fail the run: %v", err)
	}
	if statusOf(s, "compute.virtualMachines") != collect.Denied {
		t.Errorf("compute.virtualMachines = %s, want denied", statusOf(s, "compute.virtualMachines"))
	}
	if n := nodesByType(s)[model.NodeCompute]; n != 0 {
		t.Errorf("compute nodes = %d, want 0", n)
	}
}

// TestComputeNoVMsIsComplete proves an empty subscription is an honest Complete/0.
func TestComputeNoVMsIsComplete(t *testing.T) {
	api := &stubARM{bodies: map[string]string{"/subscriptions?": subsOne, "virtualMachines": `{"value":[]}`}}
	s := runCompute(t, api)
	if c := completenessOf(s, "compute.virtualMachines"); c.Status != collect.Complete || c.Collected != 0 {
		t.Errorf("compute.virtualMachines = %+v, want complete/0", c)
	}
}

// TestComputePaginates proves nextLink is followed across VM pages.
func TestComputePaginates(t *testing.T) {
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?":  subsOne,
		"virtualMachines?": `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/a","name":"a"}],"nextLink":"https://management.azure.com/np2"}`,
		"np2":              `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/b","name":"b"}]}`,
	}}
	s := runCompute(t, api)
	if n := nodesByType(s)[model.NodeCompute]; n != 2 {
		t.Errorf("VMs across pages = %d, want 2", n)
	}
}

// TestComputeBudgetExhaustion proves the shared budget bounds the sweep.
func TestComputeBudgetExhaustion(t *testing.T) {
	api := computeStub()
	c := newComputeCollector("tenant-1", api)
	c.budget = collect.NewBudget(1) // subscriptions list only
	var s collect.Scan
	if err := c.Collect(context.Background(), &s); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := completenessOf(s, "compute.virtualMachines"); got.Status != collect.Partial || got.Reason != "budget exhausted" {
		t.Errorf("compute.virtualMachines = %+v, want partial budget-exhausted", got)
	}
}

// TestComputeEvidenceRedactsToken proves the evidence body is scrubbed.
func TestComputeEvidenceRedactsToken(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 40) + ".eyJ" + strings.Repeat("b", 40) + ".sig"
	api := &stubARM{bodies: map[string]string{
		"/subscriptions?": subsOne,
		"virtualMachines": `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/x","name":"` + token + `"}]}`,
	}}
	s := runCompute(t, api)
	for _, e := range s.Envelopes {
		if strings.Contains(string(e.Response), token) {
			t.Fatalf("evidence leaked a token: %s", e.Operation)
		}
	}
}
