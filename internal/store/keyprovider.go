package store

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// keyProvider resolves the operator's master key from ordered sources
// (ADR-0015 §1). It only ever reads: it holds no way to create a key, and
// nothing on the store-open path can reach the one function that does
// (initMasterKey). So a failure to resolve a key can only refuse to open the
// store, never fabricate a new key that would orphan every existing tenant
// (ADR-0015 §2). This is the fail-closed guarantee, and it is adversarially
// tested.
type keyProvider struct {
	sources []keySource
}

// NewFileMasterKeys returns a MasterKeys backed by one passphrase-wrapped key
// file (ADR-0015). It only ever reads and can never create a key, so opening a
// store with it fails closed rather than fabricating one. passphrase is called
// when the file must be unwrapped; a nil passphrase means it cannot be, and the
// source fails closed.
func NewFileMasterKeys(path string, passphrase func() ([]byte, error)) MasterKeys {
	return &keyProvider{sources: []keySource{&fileKeySource{path: path, passphrase: passphrase}}}
}

// keySource is one place a master key can live: a key file, and later the OS
// keystore. A source distinguishes three outcomes, and the distinction is the
// whole of the fail-closed behaviour:
//   - an error means the source is configured but cannot be used (missing,
//     unreachable, permission denied, corrupt): resolution stops and the store
//     refuses to open;
//   - an empty generation list means the source simply does not hold a key, and
//     the next source is tried;
//   - a key is returned only when the source actually has it.
type keySource interface {
	// generations lists the generations this source can supply, or an error if
	// the source is configured but unusable. It never creates anything.
	generations(ctx context.Context) ([]uint32, error)
	// load returns generation gen's key, prompting for a passphrase if needed.
	load(ctx context.Context, gen uint32) (MasterKey, error)
}

// ErrMasterKeyUnavailable wraps a source failure: the store cannot open because
// a configured key source could not be used. It is never a create.
var ErrMasterKeyUnavailable = errors.New("store: the master key could not be read")

// Current returns the newest generation the first source that has any key can
// supply. A source error stops resolution and fails closed; if no source holds
// a key, it is ErrNoMasterKey — never a freshly created key.
func (p *keyProvider) Current(ctx context.Context) (MasterKey, error) {
	for _, s := range p.sources {
		gens, err := s.generations(ctx)
		if err != nil {
			return MasterKey{}, fmt.Errorf("%w: %w", ErrMasterKeyUnavailable, err)
		}
		if newest, ok := highest(gens); ok {
			return s.load(ctx, newest)
		}
	}
	return MasterKey{}, fmt.Errorf("%w: no source holds a master key", ErrNoMasterKey)
}

// Generation returns a specific generation from the first source that has it,
// with the same fail-closed rule as Current.
func (p *keyProvider) Generation(ctx context.Context, gen uint32) (MasterKey, error) {
	for _, s := range p.sources {
		gens, err := s.generations(ctx)
		if err != nil {
			return MasterKey{}, fmt.Errorf("%w: %w", ErrMasterKeyUnavailable, err)
		}
		for _, g := range gens {
			if g == gen {
				return s.load(ctx, gen)
			}
		}
	}
	return MasterKey{}, fmt.Errorf("%w: generation %d", ErrNoMasterKey, gen)
}

func highest(gens []uint32) (uint32, bool) {
	var top uint32
	var ok bool
	for _, g := range gens {
		if g > top {
			top, ok = g, true
		}
	}
	return top, ok
}

// passphraseFunc supplies the passphrase that unwraps a key file. The CLI wires
// it to a no-echo terminal read (a later slice); tests supply a fixed value. A
// nil func means the source cannot unwrap and fails closed.
type passphraseFunc func() ([]byte, error)

// fileKeySource reads a passphrase-wrapped master-key file (ADR-0015 §1). A
// missing file, an unreadable one, or a corrupt one is an error, so it fails
// closed rather than being mistaken for "no key here".
type fileKeySource struct {
	path       string
	passphrase passphraseFunc
}

func (s *fileKeySource) read(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s.path, err)
	}
	return data, nil
}

func (s *fileKeySource) generations(ctx context.Context) ([]uint32, error) {
	data, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	gen, err := keyFileGeneration(data)
	if err != nil {
		return nil, err
	}
	return []uint32{gen}, nil
}

func (s *fileKeySource) load(ctx context.Context, gen uint32) (MasterKey, error) {
	data, err := s.read(ctx)
	if err != nil {
		return MasterKey{}, err
	}
	if s.passphrase == nil {
		return MasterKey{}, fmt.Errorf("%w: no way to obtain the passphrase", ErrKeyFile)
	}
	pass, err := s.passphrase()
	if err != nil {
		return MasterKey{}, fmt.Errorf("%w: obtaining the passphrase: %w", ErrKeyFile, err)
	}
	defer clear(pass)
	k, err := unwrapMasterKey(data, pass)
	if err != nil {
		return MasterKey{}, err
	}
	if k.gen != gen {
		return MasterKey{}, fmt.Errorf("%w: file holds generation %d, not %d", ErrKeyFile, k.gen, gen)
	}
	return k, nil
}
