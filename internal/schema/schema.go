// Package schema compiles and applies the JSON Schemas embedded from /schemas.
//
// Schemas are compiled from the binary's embedded copy only. Every external
// reference — network, file, or an unknown URN — is refused, so validation never
// touches the network or filesystem and cannot be redirected by a crafted $ref.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ittcsec/ittcsecscan/schemas"
)

// Names of the embedded schemas: paths relative to /schemas.
const (
	Config    = "config/v1/config.schema.json"
	Version   = "cli/v1/version.schema.json"
	Doctor    = "cli/v1/doctor.schema.json"
	Scan      = "cli/v1/scan.schema.json"
	Overrides = "cli/v1/overrides.schema.json"

	// Canonical model documents (ADR-0014). ModelCommon holds shared $defs
	// and is never validated against directly.
	ModelCommon          = "model/v1/common.schema.json"
	ModelEntity          = "model/v1/entity.schema.json"
	ModelEdge            = "model/v1/edge.schema.json"
	ModelPermission      = "model/v1/permission.schema.json"
	ModelExposure        = "model/v1/exposure.schema.json"
	ModelClassification  = "model/v1/classification.schema.json"
	ModelEvidence        = "model/v1/evidence.schema.json"
	ModelScanManifest    = "model/v1/scan_manifest.schema.json"
	ModelFinding         = "model/v1/finding.schema.json"
	ModelAttackPath      = "model/v1/attack_path.schema.json"
	ModelCutSet          = "model/v1/cut_set.schema.json"
	ModelRemediationPlan = "model/v1/remediation_plan.schema.json"
	ModelReport          = "model/v1/report.schema.json"

	// PermissionsTemplate is the least-privilege permission template
	// (ADR-0016 §3).
	PermissionsTemplate = "permissions/v1/template.schema.json"

	// CollectEnvelope is the collection evidence envelope (a later milestone,
	// ADR-0018 §2).
	CollectEnvelope = "collect/v1/envelope.schema.json"
)

// ValidationError reports that a document does not satisfy a schema.
type ValidationError struct {
	Schema   string
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("does not match schema %s: %s", e.Schema, strings.Join(e.Problems, "; "))
}

var compiled = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	return compileFS(schemas.FS)
})

func compileFS(fsys fs.FS) (map[string]*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.UseLoader(offlineLoader{})

	ids := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		doc, err := Decode(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		obj, _ := doc.(map[string]any)
		id, _ := obj["$id"].(string)
		if id == "" {
			return fmt.Errorf("%s: schema has no $id", path)
		}
		if err := c.AddResource(id, doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		ids[path] = id
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make(map[string]*jsonschema.Schema, len(ids))
	for path, id := range ids {
		s, err := c.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out[path] = s
	}
	return out, nil
}

// offlineLoader refuses every reference that is not one of the embedded
// schemas or a bundled JSON Schema metaschema.
type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q refused: only embedded schemas are resolved", url)
}

// Decode parses JSON the way the validator expects: numbers are preserved as
// json.Number so precision is never lost.
func Decode(data []byte) (any, error) {
	return jsonschema.UnmarshalJSON(bytes.NewReader(data))
}

// Validate checks a document produced by Decode against the named schema.
func Validate(name string, doc any) error {
	all, err := compiled()
	if err != nil {
		return fmt.Errorf("embedded schemas failed to compile: %w", err)
	}
	s, ok := all[name]
	if !ok {
		return fmt.Errorf("unknown schema %q", name)
	}
	if err := s.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return &ValidationError{Schema: name, Problems: problems(ve)}
		}
		return err
	}
	return nil
}

// ValidateJSON decodes data and validates it against the named schema.
func ValidateJSON(name string, data []byte) error {
	doc, err := Decode(data)
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return Validate(name, doc)
}

// ValidateValue marshals v to JSON and validates the encoding. Tests use it to
// prove that a Go type's wire form satisfies its published schema.
func ValidateValue(name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return ValidateJSON(name, data)
}

// problems flattens the validator's report into one line per violation.
func problems(ve *jsonschema.ValidationError) []string {
	var out []string
	for _, line := range strings.Split(ve.Error(), "\n") {
		line = strings.TrimSpace(line)
		if p, ok := strings.CutPrefix(line, "- "); ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{strings.TrimSpace(ve.Error())}
	}
	return out
}
