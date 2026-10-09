package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Known answers for the sealed-value and keyed-hash formats (ADR-0013). A
// value sealed by an earlier version must open for good, so the exact bytes
// are fixed here. The expected inputs are spelled out by hand, not produced
// by encodeFields, so a change to the encoding fails even if sealing and
// opening change together.

const (
	katTenant = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	// katSealed is "payroll-admin" sealed as entity.name, row 42, of
	// katTenant, under katKey(0). Generated once on 2026-09-13; never
	// regenerate it.
	katSealed = "5545e4a9384611d8c3cbba8bc23490ae99a5cccfa3d90028772149c9177fc28020cebe025744b614bc"
)

func katKey(first byte) []byte {
	k := make([]byte, keyLen)
	for i := range k {
		k[i] = first + byte(i)
	}
	return k
}

// part is one length-prefixed part of an encoding, written out: its length
// as 4 big-endian bytes, given in hex by hand, then its bytes.
func part(lenHex, s string) string { return lenHex + hex.EncodeToString([]byte(s)) }

func TestSealedValueKnownAnswer(t *testing.T) {
	a, err := newAEAD(katKey(0))
	if err != nil {
		t.Fatal(err)
	}
	k := &tenantKeys{id: katTenant, aead: a}
	wantAAD := part("0000001b", "ittcsecscan/v1/sealed-field") + part("0000001a", katTenant) +
		part("0000000b", "entity.name") + part("00000002", "42")
	if got := hex.EncodeToString(k.valueAAD(FieldEntityName(), 42)); got != wantAAD {
		t.Fatalf("associated data:\n got %s\nwant %s", got, wantAAD)
	}

	sealed, err := hex.DecodeString(katSealed)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.open(FieldEntityName(), 42, sealed); err != nil || string(pt) != "payroll-admin" {
		t.Fatalf("the pinned value no longer opens: %q, %v", pt, err)
	}
	// The same bytes open with the standard library alone: AES-256-GCM, the
	// 12-byte nonce first, then the ciphertext and its tag.
	block, err := aes.NewCipher(katKey(0))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad, _ := hex.DecodeString(wantAAD)
	if pt, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad); err != nil || string(pt) != "payroll-admin" {
		t.Fatalf("the pinned value does not open as plain AES-256-GCM with the hand-written associated data: %q, %v", pt, err)
	}
	for what, try := range map[string]func() ([]byte, error){
		"row 43":           func() ([]byte, error) { return k.open(FieldEntityName(), 43, sealed) },
		"entity.native_id": func() ([]byte, error) { return k.open(FieldEntityNativeID(), 42, sealed) },
	} {
		if _, err := try(); !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("the pinned value opened as %s: %v", what, err)
		}
	}
}

func TestStableIDAndKeyedHashKnownAnswer(t *testing.T) {
	k := &tenantKeys{id: katTenant, idKey: katKey(32)}
	mac := func(input string) []byte {
		b, err := hex.DecodeString(input)
		if err != nil {
			t.Fatal(err)
		}
		m := hmac.New(sha256.New, katKey(32))
		_, _ = m.Write(b)
		return m.Sum(nil)
	}
	native := "arn:aws:iam::111111111111:role/r"
	if got, want := k.stableID(native), mac(part("00000018", "ittcsecscan/v1/stable-id")+part("00000020", native)); !bytes.Equal(got, want) {
		t.Errorf("stable ID %x, want %x", got, want)
	}
	want := mac(part("00000019", "ittcsecscan/v1/keyed-hash") + part("0000000e", "entity.content") + part("0000000c", "same content"))
	if got := k.hash(hashEntityContent, "same content"); !bytes.Equal(got, want) {
		t.Errorf("keyed hash %x, want %x", got, want)
	}
}

// Fields are functions, so no code can reassign one field to another. This
// fails if a package-level variable declared as a Field, or initialised with
// a Field literal, appears in the package's source again.
func TestFieldsCannotBeReassigned(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	isField := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "Field"
	}
	fset := token.NewFileSet()
	read := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		read++
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, _ := spec.(*ast.ValueSpec)
				holds := vs != nil && vs.Type != nil && isField(vs.Type)
				for _, v := range vs.Values {
					if cl, ok := v.(*ast.CompositeLit); ok && isField(cl.Type) {
						holds = true
					}
				}
				for _, n := range vs.Names {
					if holds {
						t.Errorf("%s: package variable %s holds a Field; make it a function", name, n.Name)
					}
				}
			}
		}
	}
	if read == 0 {
		t.Fatal("no source files were read")
	}
}
