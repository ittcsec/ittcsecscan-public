package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/redact"
)

// Property 5 (ADR-0010 §3), key level: derivation is correct and separate.

func kat(t *testing.T) MasterKey {
	t.Helper()
	b := make([]byte, keyLen)
	for i := range b {
		b[i] = byte(i)
	}
	m, err := NewMasterKey(1, b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The vectors were computed once with crypto/hkdf and, independently, with an
// RFC 5869 implementation on crypto/hmac; both agreed. A change here means the
// derivation changed and every existing tenant would become unreadable.
func TestKEKKnownAnswers(t *testing.T) {
	m1 := kat(t)
	m2, _ := NewMasterKey(2, m1.key[:])
	a, _ := ParseTenantID("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	b, _ := ParseTenantID("baaaaaaaaaaaaaaaaaaaaaaaaa")
	for _, v := range []struct {
		m    MasterKey
		id   TenantID
		want string
	}{
		{m1, a, "6f07dcb84ea1047044b023ffaca1d46f1fe88c8634c185393adf6de74b2e11cb"},
		{m2, a, "cf57b6f05d3d17c8ee7dabee238b9f886ad9881b656245df3b09c5337e08e838"},
		{m1, b, "d1471e584d11c0e1008426e010eb3cd126e7edac6bb93f1d71df85bc91d9c260"},
	} {
		got, err := deriveKEK(v.m, v.id)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != v.want {
			t.Errorf("KEK(gen %d, %s) = %x, want %s", v.m.gen, v.id, got, v.want)
		}
	}
	if got := kekInfo(1, a); got != "ittcsecscan/v1/tenant-kek/1/aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("kekInfo = %q", got)
	}
}

func TestWrappedKeysAreBoundToTenantGenerationAndPurpose(t *testing.T) {
	m := kat(t)
	a, _ := ParseTenantID("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	b, _ := ParseTenantID("baaaaaaaaaaaaaaaaaaaaaaaaa")
	kekA, _ := deriveKEK(m, a)
	kekB, _ := deriveKEK(m, b)
	if bytes.Equal(kekA, kekB) {
		t.Fatal("two tenants got the same KEK from one master key")
	}
	secret := bytes.Repeat([]byte{7}, keyLen)
	wrapped, err := wrapKey(kekA, secret, a, 1, purposeData)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unwrapKey(kekA, wrapped, a, 1, purposeData); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip failed: %v", err)
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 1
	for name, try := range map[string]func() ([]byte, error){
		"other tenant's KEK": func() ([]byte, error) { return unwrapKey(kekB, wrapped, a, 1, purposeData) },
		"other tenant ID":    func() ([]byte, error) { return unwrapKey(kekA, wrapped, b, 1, purposeData) },
		"other generation":   func() ([]byte, error) { return unwrapKey(kekA, wrapped, a, 2, purposeData) },
		"other purpose":      func() ([]byte, error) { return unwrapKey(kekA, wrapped, a, 1, purposeStableID) },
		"tampered":           func() ([]byte, error) { return unwrapKey(kekA, tampered, a, 1, purposeData) },
	} {
		if _, err := try(); !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("%s: error = %v, want ErrKeyMismatch", name, err)
		}
	}
}

func TestMasterKeyNeverRenders(t *testing.T) {
	m := kat(t)
	raw := string(m.key[:])
	hexKey := hex.EncodeToString(m.key[:])
	js, _ := json.Marshal(struct{ K MasterKey }{m})
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "k", m)
	for name, out := range map[string]string{
		"%v":   fmt.Sprintf("%v", m),
		"%+v":  fmt.Sprintf("%+v", m),
		"%#v":  fmt.Sprintf("%#v", m),
		"%s":   fmt.Sprintf("%s", m),
		"%x":   fmt.Sprintf("%x", m),
		"%q":   fmt.Sprintf("%q", m),
		"json": string(js),
		"slog": logged.String(),
	} {
		if !bytes.Contains([]byte(out), []byte(redact.Placeholder)) {
			t.Errorf("%s output %q lacks the placeholder", name, out)
		}
		if bytes.Contains([]byte(out), []byte(raw)) || bytes.Contains([]byte(out), []byte(hexKey)) {
			t.Errorf("%s output reveals the master key", name)
		}
	}
}

func TestStaticMasterKeys(t *testing.T) {
	ctx := context.Background()
	k1, k3 := testMasterKey(t, 1), testMasterKey(t, 3)
	s := staticKeys(t, k3, k1)
	if cur, _ := s.Current(ctx); cur.Generation() != 3 {
		t.Errorf("current generation = %d, want 3", cur.Generation())
	}
	if _, err := s.Generation(ctx, 2); !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("missing generation: %v", err)
	}
	if _, err := NewStaticMasterKeys(k1, k1); err == nil {
		t.Error("duplicate generations must be refused")
	}
	if _, err := NewMasterKey(0, make([]byte, keyLen)); err == nil {
		t.Error("generation 0 must be refused")
	}
	if _, err := NewMasterKey(1, make([]byte, 16)); err == nil {
		t.Error("a 128-bit master key must be refused")
	}
}

// FuzzKeyBinding checks key derivation and wrapping for arbitrary tenants,
// generations, and purposes: the KEK is deterministic and separates tenants
// and generations, and a wrapped key unwraps only under exactly the tenant,
// generation, and purpose it was wrapped for.
func FuzzKeyBinding(f *testing.F) {
	a, b := "aaaaaaaaaaaaaaaaaaaaaaaaaa", "baaaaaaaaaaaaaaaaaaaaaaaaa"
	f.Add(a, uint32(1), purposeData, a, uint32(1), purposeData)
	f.Add(a, uint32(1), purposeData, b, uint32(1), purposeData)
	f.Add(a, uint32(1), purposeData, a, uint32(2), purposeData)
	f.Add(a, uint32(1), purposeData, a, uint32(1), purposeStableID)
	f.Add(a, uint32(1), "x", a, uint32(1), "x\x00")
	master := make([]byte, keyLen)
	for i := range master {
		master[i] = byte(i)
	}
	secret := bytes.Repeat([]byte{0x5a}, keyLen)
	f.Fuzz(func(t *testing.T, id1 string, gen1 uint32, p1 string, id2 string, gen2 uint32, p2 string) {
		t1, err1 := ParseTenantID(id1)
		t2, err2 := ParseTenantID(id2)
		if err1 != nil || err2 != nil || gen1 == 0 || gen2 == 0 {
			return
		}
		m1, _ := NewMasterKey(gen1, master)
		m2, _ := NewMasterKey(gen2, master)
		k1, err := deriveKEK(m1, t1)
		if err != nil || len(k1) != keyLen {
			t.Fatalf("deriveKEK: %d bytes, %v", len(k1), err)
		}
		if again, _ := deriveKEK(m1, t1); !bytes.Equal(again, k1) {
			t.Fatal("deriveKEK is not deterministic")
		}
		k2, _ := deriveKEK(m2, t2)
		sameTenantAndGen := t1 == t2 && gen1 == gen2
		if sameTenantAndGen != bytes.Equal(k1, k2) {
			t.Fatalf("KEK separation broken: tenants %s/%s, generations %d/%d", t1, t2, gen1, gen2)
		}
		wrapped, err := wrapKey(k1, secret, t1, gen1, p1)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unwrapKey(k2, wrapped, t2, gen2, p2)
		if sameTenantAndGen && p1 == p2 {
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("exact binding must unwrap: %v", err)
			}
		} else if !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("unwrapped under a different binding (%s,%d,%q) vs (%s,%d,%q): %v", t1, gen1, p1, t2, gen2, p2, err)
		}
	})
}
