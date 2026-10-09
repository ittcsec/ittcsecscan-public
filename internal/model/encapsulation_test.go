package model_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/model"
)

// modelDocuments is every top-level canonical document type. A new one must be
// added here.
func modelDocuments() []any {
	return []any{
		model.Entity{}, model.Edge{}, model.Permission{}, model.Exposure{},
		model.Classification{}, model.Evidence{}, model.ScanManifest{},
		model.Finding{}, model.AttackPath{}, model.CutSet{},
		model.RemediationPlan{},
	}
}

// The model exposes no store-side representation: no file-local node ID, no
// sealed blob, no encryption key, no keyed hash (ADR-0014 §4). Those belong to
// the store. This walks every exported model type's whole field graph and
// fails if a field is a byte slice (how the store carries a sealed blob, key,
// or hash) or is named like one of those store columns. A field added later is
// covered without a new test, and a mutation that adds such a field breaks it.
func TestModelTypesEncapsulateStorage(t *testing.T) {
	forbidden := []string{"node_id", "nodeid", "sealed", "keyed", "_key", "hash"}
	seen := map[reflect.Type]bool{}
	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for {
			switch typ.Kind() {
			case reflect.Slice:
				if typ.Elem().Kind() == reflect.Uint8 {
					t.Errorf("%s is a byte slice: the model carries no sealed blobs, keys, or hashes", path)
					return
				}
				typ = typ.Elem()
			case reflect.Pointer, reflect.Array, reflect.Map:
				typ = typ.Elem()
			default:
				goto done
			}
		}
	done:
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			hay := strings.ToLower(f.Name + "\x00" + f.Tag.Get("json"))
			for _, bad := range forbidden {
				if strings.Contains(hay, bad) {
					t.Errorf("%s.%s looks like a store field (matched %q)", path, f.Name, bad)
				}
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	for _, v := range modelDocuments() {
		walk(reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
}
