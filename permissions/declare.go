package permissions

import (
	"fmt"
	"sort"
	"sync"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// Requirement is a single permission a collector or rule declares it needs, for
// a provider under a profile. Collectors register their requirements
// (via Declare); the reconciliation below keeps the checked-in templates honest
// against what the code actually requires.
type Requirement struct {
	Provider   model.Provider
	Profile    Profile
	Permission string
	By         string // the collector or rule id, e.g. "collector:aws.ec2.instances"
}

var (
	reqMu        sync.Mutex
	requirements []Requirement
)

// Declare registers a permission requirement. A collector calls it, typically
// from an init function, so that the reconciliation test sees every permission
// the code actually needs. It is safe for concurrent use.
func Declare(r Requirement) {
	reqMu.Lock()
	defer reqMu.Unlock()
	requirements = append(requirements, r)
}

// Declared returns a copy of every registered requirement, sorted, so callers
// and tests see a deterministic set.
func Declared() []Requirement {
	reqMu.Lock()
	defer reqMu.Unlock()
	out := append([]Requirement(nil), requirements...)
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func less(a, b Requirement) bool {
	if a.Provider != b.Provider {
		return a.Provider < b.Provider
	}
	if a.Profile != b.Profile {
		return a.Profile < b.Profile
	}
	if a.Permission != b.Permission {
		return a.Permission < b.Permission
	}
	return a.By < b.By
}

// Reconcile checks the checked-in templates against the declared requirements in
// both directions, so neither an invented nor an undeclared permission can slip
// through:
//
//   - every declared requirement must appear in its template, with the declaring
//     collector or rule credited in that permission's enabled_by list; and
//   - every permission a template grants must be required by at least one
//     declared collector or rule that its enabled_by list credits.
//
// It is a pure function of its inputs so tests can drive it with crafted
// templates and requirements; the shipped state (currently empty) is reconciled
// by TestTemplatesMatchDeclaredRequirements.
func Reconcile(templates []Template, reqs []Requirement) error {
	// Index: (provider, profile, permission) -> set of enabled_by ids.
	type key struct {
		provider model.Provider
		profile  Profile
		perm     string
	}
	enabledBy := map[key]map[string]bool{}
	for _, t := range templates {
		for _, e := range t.Permissions {
			k := key{t.Provider, t.Profile, e.Permission}
			set := enabledBy[k]
			if set == nil {
				set = map[string]bool{}
				enabledBy[k] = set
			}
			for _, by := range e.EnabledBy {
				set[by] = true
			}
		}
	}

	// Index the declared requirements by the same key and by.
	declared := map[key]map[string]bool{}
	for _, r := range reqs {
		k := key{r.Provider, r.Profile, r.Permission}
		set := declared[k]
		if set == nil {
			set = map[string]bool{}
			declared[k] = set
		}
		set[r.By] = true
	}

	var problems []string

	// Direction 1: every requirement must be granted and credited.
	for _, r := range reqs {
		k := key{r.Provider, r.Profile, r.Permission}
		if !enabledBy[k][r.By] {
			problems = append(problems, fmt.Sprintf(
				"%s requires %s for %s/%s, but the template does not grant it to that collector",
				r.By, r.Permission, r.Provider, r.Profile))
		}
	}

	// Direction 2: every granted permission (and each id crediting it) must be
	// backed by a declared requirement, so no invented permission survives.
	for k, credits := range enabledBy {
		for by := range credits {
			if !declared[k][by] {
				problems = append(problems, fmt.Sprintf(
					"template grants %s for %s/%s enabled_by %s, but %s declares no such requirement",
					k.perm, k.provider, k.profile, by, by))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("permission templates and declared requirements disagree:\n  %s",
			joinProblems(problems))
	}
	return nil
}

func joinProblems(p []string) string {
	out := p[0]
	for _, s := range p[1:] {
		out += "\n  " + s
	}
	return out
}
