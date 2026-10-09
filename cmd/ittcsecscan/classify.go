package main

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/exitcode"
	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/repo"
	"github.com/ittcsec/ittcsecscan/internal/store"
)

var classifySpec = commandSpec{
	name:     "classify",
	synopsis: "ittcsecscan classify (set | list) --tenant <id> [flags]",
	description: "Manage audited business-criticality overrides for a tenant's assets.\n\n" +
		"  set    Record an override: set an asset's business criticality, with the\n" +
		"         actor, timestamp, and reason kept as an append-only audit entry.\n" +
		"  list   Print the override audit history, oldest first.\n\n" +
		"Overrides are human inputs layered over the sensitivity the engine derives\n" +
		"from collected metadata during a scan; they never erase it. Each override is\n" +
		"appended, never overwritten, so the full history of who set what and when is\n" +
		"retained; the latest override for an asset is the effective one.",
}

func runClassify(ctx context.Context, inv *invocation, args []string) error {
	if len(args) == 0 {
		writeCommandHelp(inv.out, newFlagSet(classifySpec.name), classifySpec)
		return exitcode.Errorf(exitcode.Usage, "classify: a subcommand is required (set, list)")
	}
	switch args[0] {
	case "-h", "-help", "--help":
		writeCommandHelp(inv.out, newFlagSet(classifySpec.name), classifySpec)
		return nil
	case "set":
		return runClassifySet(ctx, inv, args[1:])
	case "list":
		return runClassifyList(ctx, inv, args[1:])
	default:
		return exitcode.Errorf(exitcode.Usage, "classify: unknown subcommand %q (set, list)", args[0])
	}
}

var classifySetSpec = commandSpec{
	name:     "classify set",
	synopsis: "ittcsecscan classify set --tenant <id> --resource <native-id> --criticality <n> [--reason <text>] [--actor <name>]",
	description: "Record one audited business-criticality override. The resource is named by\n" +
		"its native id (ARN, Azure resource id, or GCP full resource name), which is\n" +
		"resolved to the tenant's stable id. The actor (default: the OS user), the\n" +
		"timestamp, and the reason are recorded as an append-only audit entry.",
}

func runClassifySet(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(classifySetSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	tenant := fs.String("tenant", "", "the `id` of the tenant to record the override in")
	resource := fs.String("resource", "", "the resource's native `id` (ARN, Azure resource id, or GCP full resource name)")
	criticality := fs.Int("criticality", 0, "business-criticality `level` to set (1 or higher)")
	reason := fs.String("reason", "", "why the override is set (recorded in the audit trail)")
	actor := fs.String("actor", "", "who is setting the override (default: the OS user)")
	if done, err := parse(fs, inv, classifySetSpec, args); done {
		return err
	}

	id, err := requireTenant(*tenant, "classify set")
	if err != nil {
		return err
	}
	if strings.TrimSpace(*resource) == "" {
		return exitcode.Errorf(exitcode.Usage, "classify set: --resource is required")
	}
	if *criticality < 1 {
		return exitcode.Errorf(exitcode.Usage, "classify set: --criticality must be 1 or higher")
	}
	who := strings.TrimSpace(*actor)
	if who == "" {
		who = osUsername()
	}
	if who == "" {
		return exitcode.Errorf(exitcode.Usage, "classify set: could not determine the actor; pass --actor")
	}

	st, err := openStore(inv, rf)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	tn, release, err := st.Acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()

	stable, err := tn.StableID(*resource)
	if err != nil {
		return err
	}
	ov := model.CriticalityOverride{
		Entity:      model.StableID(stable),
		Criticality: *criticality,
		Actor:       who,
		Reason:      strings.TrimSpace(*reason),
		At:          time.Now().UTC(),
	}
	if err := tn.AddCriticalityOverride(ctx, ov); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(inv.out, "recorded criticality override: tenant %s resource %s criticality %d by %s\n",
		id, safeField(*resource), *criticality, safeField(who))
	return nil
}

var classifyListSpec = commandSpec{
	name:        "classify list",
	synopsis:    "ittcsecscan classify list --tenant <id> [--json]",
	description: "Print the business-criticality override audit history, oldest first.",
}

// overridesJSON is the wire form of the override audit history (schemas/cli/v1/overrides.schema.json).
type overridesJSON struct {
	SchemaVersion int            `json:"schema_version"`
	Tenant        string         `json:"tenant"`
	Overrides     []overrideJSON `json:"overrides"`
}

type overrideJSON struct {
	Entity      string `json:"entity"`
	Resource    string `json:"resource,omitempty"`
	Criticality int    `json:"criticality"`
	Actor       string `json:"actor"`
	Reason      string `json:"reason,omitempty"`
	At          string `json:"at"`
}

func runClassifyList(ctx context.Context, inv *invocation, args []string) error {
	fs := newFlagSet(classifyListSpec.name)
	var rf runtimeFlags
	rf.register(fs)
	tenant := fs.String("tenant", "", "the `id` of the tenant whose overrides to list")
	asJSON := fs.Bool("json", false, "print JSON (schemas/cli/v1/overrides.schema.json)")
	if done, err := parse(fs, inv, classifyListSpec, args); done {
		return err
	}
	id, err := requireTenant(*tenant, "classify list")
	if err != nil {
		return err
	}

	st, err := openStore(inv, rf)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	tn, release, err := st.Acquire(ctx, id)
	if err != nil {
		return err
	}
	defer release()

	ovs, err := tn.CriticalityOverrides(ctx)
	if err != nil {
		return err
	}
	// Best-effort resolve each entity's native id for a readable audit trail; a
	// gone entity simply shows its stable id.
	native := map[model.StableID]string{}
	_ = tn.View(ctx, func(r repo.Reader) error {
		for _, ov := range ovs {
			if _, seen := native[ov.Entity]; seen {
				continue
			}
			if e, err := r.Entities().Get(ctx, ov.Entity); err == nil {
				native[ov.Entity] = e.NativeID
			}
		}
		return nil
	})

	if *asJSON {
		out := overridesJSON{SchemaVersion: 1, Tenant: id.String(), Overrides: []overrideJSON{}}
		for _, ov := range ovs {
			out.Overrides = append(out.Overrides, overrideJSON{
				Entity:      string(ov.Entity),
				Resource:    native[ov.Entity],
				Criticality: ov.Criticality,
				Actor:       ov.Actor,
				Reason:      ov.Reason,
				At:          ov.At.Format(time.RFC3339),
			})
		}
		return writeJSON(inv.out, out)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Criticality overrides for tenant %s: %d\n", id, len(ovs))
	for _, ov := range ovs {
		who := native[ov.Entity]
		if who == "" {
			who = string(ov.Entity)
		}
		fmt.Fprintf(&b, "  %s  criticality=%d  by=%s  at=%s", who, ov.Criticality, ov.Actor, ov.At.Format(time.RFC3339))
		if ov.Reason != "" {
			fmt.Fprintf(&b, "  reason=%s", ov.Reason)
		}
		b.WriteByte('\n')
	}
	_, err = inv.out.Write([]byte(safeField(b.String())))
	return err
}

// requireTenant parses a required --tenant id, returning a usage error when it is
// missing or malformed.
func requireTenant(tenant, cmd string) (store.TenantID, error) {
	if strings.TrimSpace(tenant) == "" {
		return store.TenantID{}, exitcode.Errorf(exitcode.Usage, "%s: --tenant is required", cmd)
	}
	id, err := store.ParseTenantID(tenant)
	if err != nil {
		return store.TenantID{}, exitcode.Wrap(exitcode.Usage, err)
	}
	return id, nil
}

// osUsername returns the current OS user's name, or "" when it cannot be determined.
func osUsername() string {
	u, err := user.Current()
	if err != nil || u == nil {
		return ""
	}
	if u.Username != "" {
		return u.Username
	}
	return u.Uid
}
