package graph

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ittcsec/ittcsecscan/internal/model"
	"github.com/ittcsec/ittcsecscan/internal/normalize"
)

// ClassificationResult is the sensitive-asset classification engine's output
// (ADR-0025): one model.Classification per candidate asset (data stores, secret
// and key-material stores, and any asset a customer explicitly classified),
// including explicit unknowns for candidates the metadata could not classify.
// Complete is false when a collection read the decision could have used (for
// example a tag read) was not complete; the classifications are then a floor.
type ClassificationResult struct {
	Classifications []model.Classification
	Complete        bool
	Gaps            []string
}

// Classify assigns a data-sensitivity label to each candidate asset from collected
// metadata alone (ADR-0025). It is deterministic and reads only collected facts; it
// never inspects data content (the internal/graph gate forbids net and I/O) and
// never sets ApprovedSample. Every classification records, in Method, the exact
// signals that decided it, so a label is never a black-box. When the metadata is
// insufficient it resolves to SensitivityUnknown, never a confident guess and never
// a non-sensitive default.
func Classify(g *normalize.NormalizedScan) ClassificationResult {
	res := ClassificationResult{Complete: true}
	if g == nil {
		return res
	}
	for _, e := range g.Entities {
		c, ok := classifyEntity(e)
		if ok {
			res.Classifications = append(res.Classifications, c)
		}
	}
	res.Complete, res.Gaps = coverage(g.Completeness)
	sort.SliceStable(res.Classifications, func(i, j int) bool {
		return res.Classifications[i].Entity < res.Classifications[j].Entity
	})
	return res
}

// MaterializeClassification runs the classification engine over g and projects each
// classification back onto its entity as facts the detection engine's closed
// predicates can read: sensitivity, sensitivity_confidence, and sensitivity_method.
// It is the classification analogue of Materialize (exposure), the seam that makes a
// classification a consumable fact (ADR-0025 section 6). Like Materialize it only
// adds facts, so a detection that ignores them is unperturbed; an unknown
// classification is projected too, so an unclassified candidate is visible as
// sensitivity=unknown, never silently absent. It returns the structured result.
func MaterializeClassification(g *normalize.NormalizedScan) ClassificationResult {
	res := Classify(g)
	if g == nil {
		return res
	}
	byEntity := make(map[model.StableID]model.Classification, len(res.Classifications))
	for _, c := range res.Classifications {
		byEntity[c.Entity] = c
	}
	for i := range g.Entities {
		c, ok := byEntity[g.Entities[i].ID]
		if !ok {
			continue
		}
		if g.Entities[i].Attributes == nil {
			g.Entities[i].Attributes = map[string]string{}
		}
		a := g.Entities[i].Attributes
		a["sensitivity"] = c.Label
		a["sensitivity_confidence"] = strconv.Itoa(int(c.Confidence))
		a["sensitivity_method"] = c.Method
	}
	return res
}

// classifyEntity classifies one entity, returning ok=false for a non-candidate (an
// asset this engine does not classify, so no record is emitted). The decision order
// is: an explicit customer classification tag is authoritative; then the resource
// nature (key/secret material is intrinsically sensitive; a data store holds data
// whose sensitivity the metadata cannot see); a sensitive naming token refines a
// data store. A data store with no sensitivity signal is the fail-closed unknown.
func classifyEntity(e model.Entity) (model.Classification, bool) {
	nature := natureOf(e)
	dk, dv := declaredClassification(e)
	if nature == "" && dk == "" {
		return model.Classification{}, false // not a candidate: no record
	}

	var label model.Sensitivity
	var conf model.Confidence
	var method []string
	tok := nameToken(e)

	switch {
	case dk != "":
		// A customer declaration is authoritative, even over resource nature.
		if mapped, ok := mapDeclared(dv); ok {
			label, conf = mapped, 90
			method = append(method, "declared "+dk+"="+dv)
		} else {
			// The asset was declared in a scheme we do not recognize: metadata is
			// present but insufficient to interpret. Fail closed, do not guess.
			label, conf = model.SensitivityUnknown, 20
			method = append(method, "declared "+dk+"="+dv+" (unrecognized value)")
		}
	case nature == "key_material" || nature == "secret_store":
		// The asset's sensitivity is intrinsic: it holds or controls secrets.
		label, conf = model.SensitivityHigh, 70
		method = append(method, "resource_nature="+nature)
		if tok != "" {
			conf = 80
			method = append(method, "name_token="+tok)
		}
	case nature == "data_store":
		if tok != "" {
			label, conf = model.SensitivityHigh, 55
			method = append(method, "resource_nature=data_store", "name_token="+tok)
		} else {
			// A data store holds data whose sensitivity the metadata cannot see.
			// This is the fail-closed core: unknown, never a confident label and
			// never low (an untagged data store is possibly sensitive, not safe).
			label, conf = model.SensitivityUnknown, 15
			method = append(method, "resource_nature=data_store; no sensitivity signal in metadata")
		}
	default:
		label, conf = model.SensitivityUnknown, 10
		method = append(method, "insufficient metadata")
	}

	return model.Classification{
		SchemaVersion: model.SchemaVersion,
		Entity:        e.ID,
		Label:         string(label),
		Method:        strings.Join(method, "; "),
		Confidence:    conf,
		// ApprovedSample stays empty: content sampling is disabled this phase.
	}, true
}

// natureOf returns the classification-relevant resource nature, or "" for a
// resource this engine does not treat as an inherent classification candidate.
func natureOf(e model.Entity) string {
	switch {
	case e.Type == model.NodeSecretStore:
		return "secret_store"
	case isKeyMaterial(e):
		return "key_material"
	case e.Type == model.NodeDataStore:
		return "data_store"
	}
	return ""
}

// isKeyMaterial reports whether the entity is a key-management store (AWS KMS,
// Azure Key Vault, GCP Cloud KMS), identified by its collected type/id facts.
func isKeyMaterial(e model.Entity) bool {
	switch {
	case e.Attributes["azure_type"] == "key_vault":
		return true
	case strings.HasPrefix(e.NativeID, "arn:aws:kms:"):
		return true
	case strings.HasPrefix(e.NativeID, "//cloudkms.googleapis.com/"):
		return true
	}
	return false
}

// classificationTagKeys are the attribute keys (from collected tags/labels) that
// name a data classification a customer declared. Order is the lookup precedence.
var classificationTagKeys = []string{
	"tag:data_classification", "tag:classification", "tag:sensitivity", "tag:confidentiality", "tag:pii",
	"label:data_classification", "label:classification", "label:sensitivity", "label:confidentiality", "label:pii",
}

// declaredClassification returns the first declared-classification tag key and its
// non-empty value, or "", "".
func declaredClassification(e model.Entity) (key, val string) {
	for _, k := range classificationTagKeys {
		if v, ok := e.Attributes[k]; ok && strings.TrimSpace(v) != "" {
			return k, strings.TrimSpace(v)
		}
	}
	return "", ""
}

// mapDeclared maps a declared classification value to a sensitivity, or ok=false
// when the value is not one this engine recognizes (never guessed).
func mapDeclared(val string) (model.Sensitivity, bool) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "restricted", "confidential", "secret", "top-secret", "highly-confidential", "pii", "phi", "pci", "sensitive", "high":
		return model.SensitivityHigh, true
	case "internal", "private", "moderate", "medium":
		return model.SensitivityModerate, true
	case "public", "unclassified", "nonsensitive", "non-sensitive", "low":
		return model.SensitivityLow, true
	}
	return model.SensitivityUnknown, false
}

// sensitiveNameTokens are name segments that signal sensitive data. They are matched
// as whole separator-delimited segments (never substrings), so "dolphin" does not
// match "phi". The signal is advisory: names suggest, they do not prove.
var sensitiveNameTokens = []string{
	"pii", "phi", "pci", "ssn", "secret", "credential", "credentials", "password",
	"customer", "confidential", "financial", "finance", "health", "medical",
	"payroll", "gdpr", "hipaa", "pci-dss",
}

// nameToken returns the first sensitive token that appears as a whole segment of the
// entity's name or native id, or "".
func nameToken(e model.Entity) string {
	segs := segments(e.Name + "/" + e.NativeID)
	set := make(map[string]bool, len(segs))
	for _, s := range segs {
		set[s] = true
	}
	for _, t := range sensitiveNameTokens {
		if set[t] {
			return t
		}
	}
	return ""
}

// segments splits s into lowercase alphanumeric segments on any other character, so
// matching is on whole words, not substrings.
func segments(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}
