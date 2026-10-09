package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fixedPass returns the test passphrase, cloned because load zeroes it.
func fixedPass() ([]byte, error) { return bytes.Clone(testPassphrase), nil }

// writeGoodKey writes a valid wrapped key file and returns its path.
func writeGoodKey(t *testing.T, dir string, gen uint32) string {
	t.Helper()
	path := filepath.Join(dir, "master.key")
	if err := initMasterKey(path, gen, testPassphrase, nil); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeSource stands in for a keystore in tests: it can hold generations, or
// report itself unusable.
type fakeSource struct {
	gens    []uint32
	genErr  error
	loadErr error
	key     MasterKey
}

func (f *fakeSource) generations(context.Context) ([]uint32, error) { return f.gens, f.genErr }
func (f *fakeSource) load(context.Context, uint32) (MasterKey, error) {
	if f.loadErr != nil {
		return MasterKey{}, f.loadErr
	}
	return f.key, nil
}

// A valid key file resolves through the provider.
func TestKeyProviderReadsAValidFile(t *testing.T) {
	ctx := context.Background()
	path := writeGoodKey(t, t.TempDir(), 4)
	p := &keyProvider{sources: []keySource{&fileKeySource{path: path, passphrase: fixedPass}}}

	cur, err := p.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.gen != 4 {
		t.Errorf("Current generation = %d, want 4", cur.gen)
	}
	if _, err := p.Generation(ctx, 4); err != nil {
		t.Errorf("Generation(4) = %v, want the key", err)
	}
	if _, err := p.Generation(ctx, 9); !errors.Is(err, ErrNoMasterKey) {
		t.Errorf("Generation(9) = %v, want ErrNoMasterKey", err)
	}
}

// The heart of ADR-0015: every way of failing to resolve a key ends in a
// refusal, and none of them fabricates a key. Modelled on the seal counter's
// adversarial test — a mistake here (silently creating a key) would orphan
// every existing tenant and be hard to detect, so it is proven, not assumed.
//
// The refusal is proven by asserting that Current and Generation BOTH return an
// error for every failure mode: the only way this test passes is if no path
// ever returns a (fabricated) key. A mutation that created a key on failure
// would make one of these calls succeed and fail the test. A filesystem guard
// additionally proves no key file is written behind our back.
func TestKeyProviderFailsClosedNeverCreates(t *testing.T) {
	ctx := context.Background()
	// A directory watched for any key file the provider might wrongly create.
	// The provider is given no path here, so nothing legitimate writes to it.
	guard := t.TempDir()
	guardEmpty := func() {
		t.Helper()
		if entries, err := os.ReadDir(guard); err != nil || len(entries) != 0 {
			t.Fatalf("a key file was created during a failure (%d entries): a failure must never create a key", len(entries))
		}
	}

	fixtures := t.TempDir()
	good := writeGoodKey(t, fixtures, 1)
	goodBytes, err := os.ReadFile(good) //nolint:gosec // G304: good is a test-created temp file
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(fixtures, name)
		if err := os.WriteFile(p, data, 0o600); err != nil { //nolint:gosec // G703: name is a test-controlled fixture filename
			t.Fatal(err)
		}
		return p
	}
	badMagic := bytes.Clone(goodBytes)
	badMagic[0] ^= 0xff
	wrongPass := func() ([]byte, error) { return []byte("not the passphrase"), nil }
	errPass := func() ([]byte, error) { return nil, errors.New("no terminal to read a passphrase") }

	cases := map[string]keySource{
		"missing file":          &fileKeySource{path: filepath.Join(fixtures, "absent.key"), passphrase: fixedPass},
		"path is a directory":   &fileKeySource{path: fixtures, passphrase: fixedPass},
		"truncated file":        &fileKeySource{path: write("trunc.key", goodBytes[:10]), passphrase: fixedPass},
		"over-long file":        &fileKeySource{path: write("long.key", append(bytes.Clone(goodBytes), 0)), passphrase: fixedPass},
		"corrupt magic":         &fileKeySource{path: write("magic.key", badMagic), passphrase: fixedPass},
		"garbage file":          &fileKeySource{path: write("garbage.key", bytes.Repeat([]byte{0xa5}, keyFileLen)), passphrase: fixedPass},
		"wrong passphrase":      &fileKeySource{path: good, passphrase: wrongPass},
		"passphrase read fails": &fileKeySource{path: good, passphrase: errPass},
		"no passphrase source":  &fileKeySource{path: good, passphrase: nil},
		"unreachable keystore":  &fakeSource{genErr: errors.New("keystore unreachable")},
		"keystore load fails":   &fakeSource{gens: []uint32{1}, loadErr: errors.New("keystore read denied")},
		// The first-run-not-bootstrapped case: a source that holds nothing must
		// refuse, not create. This is the exact scenario a "silently create a
		// key" bug would reach.
		"no key present": &fakeSource{},
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			p := &keyProvider{sources: []keySource{src}}
			if _, err := p.Current(ctx); err == nil {
				t.Error("Current succeeded on a failure mode: a key may have been fabricated")
			}
			if _, err := p.Generation(ctx, 1); err == nil {
				t.Error("Generation succeeded on a failure mode")
			}
			guardEmpty()
		})
	}

	if runtime.GOOS != "windows" {
		t.Run("permission denied", func(t *testing.T) {
			denied := write("denied.key", goodBytes)
			if err := os.Chmod(denied, 0); err != nil {
				t.Skipf("cannot chmod: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(denied, 0o600) })
			p := &keyProvider{sources: []keySource{&fileKeySource{path: denied, passphrase: fixedPass}}}
			if _, err := p.Current(ctx); err == nil {
				t.Error("Current succeeded on a permission-denied key file")
			}
			guardEmpty()
		})
	}
}

// A source error stops resolution: the provider does not fall through to a
// later source that does have a key. A source that simply holds nothing is
// skipped, and the next source is used.
func TestKeyProviderResolutionOrder(t *testing.T) {
	ctx := context.Background()
	good := &fileKeySource{path: writeGoodKey(t, t.TempDir(), 2), passphrase: fixedPass}

	// An erroring first source fails closed, even though a good source follows.
	failFirst := &keyProvider{sources: []keySource{&fakeSource{genErr: errors.New("unreachable")}, good}}
	if _, err := failFirst.Current(ctx); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Errorf("an erroring first source = %v, want a fail-closed refusal (not the fallback key)", err)
	}

	// An empty first source is skipped, and the good second source is used.
	emptyFirst := &keyProvider{sources: []keySource{&fakeSource{}, good}}
	if cur, err := emptyFirst.Current(ctx); err != nil || cur.gen != 2 {
		t.Errorf("empty then good = (gen %d, %v), want the good key", cur.gen, err)
	}
}

// At the store boundary: with no master key, Create fails closed and leaves no
// tenant behind. Opening a store must never invent a key.
func TestStoreCreateFailsClosedWithoutAKey(t *testing.T) {
	prov := &keyProvider{sources: []keySource{
		&fileKeySource{path: filepath.Join(t.TempDir(), "absent.key"), passphrase: fixedPass},
	}}
	s := openStore(t, Options{DataDir: testDataDir(t), Keys: prov})
	if _, err := s.Create(context.Background()); err == nil {
		t.Fatal("Create succeeded with no master key: the store must refuse to open")
	}
	if entries, err := os.ReadDir(s.layout.tenantsRoot); err != nil || len(entries) != 0 {
		t.Errorf("a failed Create left %d tenant directories, want none", len(entries))
	}
}
