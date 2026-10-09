package schema

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedSchemasCompile(t *testing.T) {
	all, err := compiled()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{Config, Version, Doctor} {
		if _, ok := all[name]; !ok {
			t.Errorf("embedded schema %s missing", name)
		}
	}
}

func TestExternalReferencesAreRefused(t *testing.T) {
	for _, ref := range []string{
		"https://example.com/evil.schema.json",
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
		"urn:not:embedded",
	} {
		fsys := fstest.MapFS{"x.schema.json": {Data: []byte(
			`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:test:x","$ref":"` + ref + `"}`,
		)}}
		if _, err := compileFS(fsys); err == nil {
			t.Errorf("schema referencing %s compiled; external references must be refused", ref)
		}
	}
}

func TestSchemaWithoutIDIsRejected(t *testing.T) {
	fsys := fstest.MapFS{"x.schema.json": {Data: []byte(`{"type":"object"}`)}}
	if _, err := compileFS(fsys); err == nil {
		t.Error("schema without $id compiled")
	}
}

func TestValidate(t *testing.T) {
	if err := ValidateJSON(Config, []byte(`{"schema_version":1}`)); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}

	err := ValidateJSON(Config, []byte(`{"schema_version":1,"log":{"level":"loud"}}`))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	if ve.Schema != Config || len(ve.Problems) == 0 || !strings.Contains(err.Error(), "/log/level") {
		t.Errorf("unhelpful error: %v", err)
	}

	if err := Validate("missing.schema.json", map[string]any{}); err == nil {
		t.Error("unknown schema name accepted")
	}
	if err := ValidateJSON(Config, []byte(`{`)); err == nil {
		t.Error("malformed JSON accepted")
	}
}

func TestFormatsAreAsserted(t *testing.T) {
	doc := `{"schema_version":1,"version":"v","development_build":true,"commit":"c","source_tree":"clean",` +
		`"build_time":"%s","go_version":"go","os":"linux","arch":"amd64"}`
	if err := ValidateJSON(Version, []byte(strings.Replace(doc, "%s", "2026-01-01T00:00:00Z", 1))); err != nil {
		t.Errorf("valid date-time rejected: %v", err)
	}
	if err := ValidateJSON(Version, []byte(strings.Replace(doc, "%s", "unknown", 1))); err != nil {
		t.Errorf("unknown build time rejected: %v", err)
	}
	if err := ValidateJSON(Version, []byte(strings.Replace(doc, "%s", "yesterday", 1))); err == nil {
		t.Error("non date-time build_time accepted; format assertion is off")
	}
}

func TestValidateValue(t *testing.T) {
	type cfg struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := ValidateValue(Config, cfg{SchemaVersion: 1}); err != nil {
		t.Error(err)
	}
	if err := ValidateValue(Config, cfg{SchemaVersion: 2}); err == nil {
		t.Error("schema_version 2 accepted")
	}
	if err := ValidateValue(Config, func() {}); err == nil {
		t.Error("unmarshalable value accepted")
	}
}
