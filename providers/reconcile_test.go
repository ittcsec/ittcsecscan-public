package providers

import (
	"testing"

	"github.com/ittcsec/ittcsecscan/permissions"

	// Link every collector so its init registers the permissions it declares.
	// New collector packages are added here as they land.
	_ "github.com/ittcsec/ittcsecscan/providers/aws/collect"
	_ "github.com/ittcsec/ittcsecscan/providers/azure/collect"
	_ "github.com/ittcsec/ittcsecscan/providers/gcp/collect"
)

// TestTemplatesReconcileWithCollectors is the whole-repo gate (ADR-0016 §3): the
// checked-in permission templates and the permissions every collector declares
// must agree in both directions. An invented template permission (that no
// collector needs) and an undeclared requirement (that a collector needs but the
// template omits) are both a build failure here, not a review catch.
func TestTemplatesReconcileWithCollectors(t *testing.T) {
	all, err := permissions.All()
	if err != nil {
		t.Fatal(err)
	}
	if err := permissions.Reconcile(all, permissions.Declared()); err != nil {
		t.Fatalf("templates and declared collector requirements disagree: %v", err)
	}
}
