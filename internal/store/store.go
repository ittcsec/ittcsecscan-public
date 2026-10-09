package store

import (
	"container/list"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/ittcsec/ittcsecscan/internal/version"
)

// DefaultMaxOpen is the default cap on tenants open at once (ADR-0010 §4):
// each costs three file handles and a page cache, and macOS allows 256 open
// files per process by default.
const DefaultMaxOpen = 16

// DefaultAcquireWait bounds how long Acquire waits for a free tenant slot when
// the caller's context has no deadline. Acquire never waits forever.
const DefaultAcquireWait = 30 * time.Second

// Options configures a Store.
type Options struct {
	// DataDir is the absolute data directory (ADR-0006 data_dir). Tenants live
	// in DataDir/tenants. It is created owner-only if missing.
	DataDir string
	// Keys supplies the operator's master key. Required.
	Keys MasterKeys
	// MaxOpen caps the tenants open at once; 0 means DefaultMaxOpen.
	MaxOpen int
	// Rand is the source of tenant IDs and keys; nil means crypto/rand.
	Rand io.Reader
	// Now is the clock for creation and migration times; nil means time.Now.
	Now func() time.Time
	// Logger receives operational warnings, notably that a tenant's data key is
	// near its encryption limit (B-6). nil discards them.
	Logger *slog.Logger
	// AcquireWait bounds how long Acquire waits for a free slot when its
	// context has no deadline; 0 means DefaultAcquireWait.
	AcquireWait time.Duration
	// sealHardStop and sealWarn override the per-data-key encryption limits
	// (B-6); 0 means the defaults. Unexported: tests set small limits, and
	// production always uses the defaults.
	sealHardStop int64
	sealWarn     int64
}

// Store gives access to per-tenant databases (ADR-0010). There is no shared
// database: each tenant is its own file, opened only by TenantID.
type Store struct {
	layout layout
	keys   MasterKeys
	rand   io.Reader
	now    func() time.Time
	max    int
	// acquireWait bounds waits for a free slot when ctx has no deadline.
	acquireWait time.Duration
	// migrations are the schema steps this binary ships (ADR-0011 §2);
	// binaryVersion is recorded with each one it applies.
	migrations    *migrationSet
	binaryVersion string
	// sealHardStop and sealWarn are the per-data-key encryption limits (B-6).
	sealHardStop int64
	sealWarn     int64
	logger       *slog.Logger

	mu      sync.Mutex
	closed  bool
	open    map[TenantID]*entry
	lru     *list.List    // of *entry, most recently used first
	changed chan struct{} // closed and replaced whenever a lease is released
}

type entry struct {
	t    *Tenant
	refs int
	elem *list.Element
}

// New opens the store in opts.DataDir.
func New(opts Options) (*Store, error) {
	l, err := newLayout(opts.DataDir)
	if err != nil {
		return nil, err
	}
	if opts.Keys == nil {
		return nil, errors.New("store: no master key source")
	}
	maxOpen := opts.MaxOpen
	switch {
	case maxOpen == 0:
		maxOpen = DefaultMaxOpen
	case maxOpen < 1:
		return nil, errors.New("store: MaxOpen must be positive")
	}
	acquireWait := opts.AcquireWait
	switch {
	case acquireWait == 0:
		acquireWait = DefaultAcquireWait
	case acquireWait < 0:
		return nil, errors.New("store: AcquireWait must be positive")
	}
	migrations, err := productionMigrations()
	if err != nil {
		return nil, err
	}
	sealHardStop, sealWarn := opts.sealHardStop, opts.sealWarn
	if sealHardStop == 0 {
		sealHardStop = defaultSealHardStop
	}
	if sealWarn == 0 {
		sealWarn = defaultSealWarn
	}
	if sealWarn >= sealHardStop || sealHardStop < 1 {
		return nil, errors.New("store: the seal warn limit must be below a positive hard stop")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Store{
		layout:        l,
		keys:          opts.Keys,
		rand:          opts.Rand,
		now:           opts.Now,
		max:           maxOpen,
		acquireWait:   acquireWait,
		migrations:    migrations,
		binaryVersion: version.Get().Version,
		sealHardStop:  sealHardStop,
		sealWarn:      sealWarn,
		logger:        logger,
		open:          map[TenantID]*entry{},
		lru:           list.New(),
		changed:       make(chan struct{}),
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if s.now == nil {
		s.now = time.Now
	}
	for _, dir := range []string{l.dataDir, l.tenantsRoot} {
		if err := ensurePrivateDir(dir); err != nil {
			return nil, err
		}
	}
	if err := privateAncestors(l.tenantsRoot); err != nil {
		return nil, err
	}
	return s, nil
}

// Create makes a new tenant with a fresh random ID and returns the ID. The
// tenant's directory and database are created exclusively and owner-only, so
// an ID collision can never overwrite an existing tenant.
func (s *Store) Create(ctx context.Context) (TenantID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return TenantID{}, ErrClosed
	}
	id, err := NewTenantID(s.rand)
	if err != nil {
		return TenantID{}, err
	}
	dir, err := s.layout.dir(id)
	if err != nil {
		return TenantID{}, err
	}
	if err := makePrivateDir(dir); err != nil {
		return TenantID{}, fmt.Errorf("store: creating tenant directory: %w", err)
	}
	if err := s.initTenant(ctx, id, dir); err != nil {
		// Only what this call created is removed: the directory did not exist
		// before makePrivateDir succeeded.
		return TenantID{}, errors.Join(err, os.RemoveAll(dir))
	}
	// Prove the new tenant opens through the normal checks.
	t, err := s.openTenant(ctx, id)
	if err != nil {
		return TenantID{}, errors.Join(err, os.RemoveAll(dir))
	}
	return id, t.close()
}

func (s *Store) initTenant(ctx context.Context, id TenantID, dir string) error {
	if err := makePrivateDir(blobsPath(dir)); err != nil {
		return fmt.Errorf("store: creating blobs directory: %w", err)
	}
	path := dbPath(dir)
	if err := createPrivateFile(path); err != nil {
		return fmt.Errorf("store: creating tenant database: %w", err)
	}
	master, err := s.keys.Current(ctx)
	if err != nil {
		return err
	}
	kek, err := deriveKEK(master, id)
	if err != nil {
		return err
	}
	defer clear(kek)
	dataKey, err := randomKey(s.rand)
	if err != nil {
		return err
	}
	defer clear(dataKey)
	idKey, err := randomKey(s.rand)
	if err != nil {
		return err
	}
	defer clear(idKey)
	wrappedData, err := wrapKey(kek, dataKey, id, master.gen, purposeData)
	if err != nil {
		return err
	}
	wrappedID, err := wrapKey(kek, idKey, id, master.gen, purposeStableID)
	if err != nil {
		return err
	}
	db, conn, err := openDB(ctx, path)
	if err != nil {
		return err
	}
	err = s.initSchema(ctx, conn, id, baseIdentity{
		generation:  master.gen,
		wrappedData: wrappedData,
		wrappedID:   wrappedID,
		createdAt:   s.now(),
	})
	return errors.Join(err, conn.Close(), db.Close())
}

// tenantFiles are a tenant's directory and database file, as checked before
// they are opened.
type tenantFiles struct {
	dir, db         string
	dirInfo, dbInfo fs.FileInfo
}

// checkTenantFiles runs the path checks of ADR-0010 §1 on tenant id's
// directory and files before anything is opened.
func (s *Store) checkTenantFiles(id TenantID) (tenantFiles, error) {
	dir, err := s.layout.dir(id)
	if err != nil {
		return tenantFiles{}, err
	}
	// The tenants root is the store's own folder: a symlink or junction
	// swapped in there would redirect every tenant, and another account able
	// to add entries could plant directories beside them.
	if _, err := plainDir(s.layout.tenantsRoot); err != nil {
		return tenantFiles{}, fmt.Errorf("%w: tenants root: %w", ErrUnsafePath, err)
	}
	if err := private(s.layout.tenantsRoot); err != nil {
		return tenantFiles{}, err
	}
	dirInfo, err := plainDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return tenantFiles{}, ErrNotFound
	}
	if err != nil {
		return tenantFiles{}, err
	}
	if err := errors.Join(private(dir), privateAncestors(dir)); err != nil {
		return tenantFiles{}, err
	}
	path := dbPath(dir)
	fileInfo, err := plainFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return tenantFiles{}, fmt.Errorf("%w: tenant directory has no database", ErrForeignFile)
	}
	if err != nil {
		return tenantFiles{}, err
	}
	if err := private(path); err != nil {
		return tenantFiles{}, err
	}
	if _, err := plainDir(blobsPath(dir)); err != nil {
		return tenantFiles{}, fmt.Errorf("%w: blobs directory: %w", ErrUnsafePath, err)
	}
	if err := errors.Join(private(blobsPath(dir)), checkSidecarsPlain(path)); err != nil {
		return tenantFiles{}, err
	}
	// The pre-migration backups directory exists once a migration has run,
	// and is checked like blobs.
	if _, err := os.Lstat(backupsPath(dir)); err == nil {
		if _, err := plainDir(backupsPath(dir)); err != nil {
			return tenantFiles{}, fmt.Errorf("%w: backups directory: %w", ErrUnsafePath, err)
		}
		if err := private(backupsPath(dir)); err != nil {
			return tenantFiles{}, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return tenantFiles{}, err
	}
	return tenantFiles{dir: dir, db: path, dirInfo: dirInfo, dbInfo: fileInfo}, nil
}

// openTenant runs every check of ADR-0010 §1 before, and after, opening the
// tenant's database. No tenant data is read until the file's identity and
// keys have been verified.
func (s *Store) openTenant(ctx context.Context, id TenantID) (*Tenant, error) {
	f, err := s.checkTenantFiles(id)
	if err != nil {
		return nil, err
	}
	db, conn, err := openDB(ctx, f.db)
	if err != nil {
		return nil, err
	}
	t := &Tenant{id: id, db: db, conn: conn, sealHardStop: s.sealHardStop, sealWarn: s.sealWarn, logger: s.logger}
	if err := s.verify(ctx, t, f); err != nil {
		return nil, errors.Join(err, t.close())
	}
	t.markVerified()
	// Warn if this tenant's data key is already near its encryption limit, so
	// opening it (for any command) surfaces the need to rotate (B-6).
	if count, err := t.sealCount(ctx); err == nil {
		t.warnNearLimit(count)
	}
	return t, nil
}

// verify checks, on the open connection, that nothing was swapped since the
// path checks, that the file is this tenant's, that this binary may use it
// (ADR-0011 §2), and that its keys unwrap. A file older than this binary is
// then migrated.
func (s *Store) verify(ctx context.Context, t *Tenant, f tenantFiles) error {
	for _, c := range []struct {
		path   string
		before fs.FileInfo
	}{{f.dir, f.dirInfo}, {f.db, f.dbInfo}} {
		now, err := os.Lstat(c.path)
		if err != nil || !os.SameFile(c.before, now) {
			return fmt.Errorf("%w: %s changed while it was being opened", ErrUnsafePath, c.path)
		}
	}
	if err := checkSidecarsPlain(f.db); err != nil {
		return err
	}
	var ident identity
	var history []recordedMigration
	err := t.withConn(ctx, func(c *sql.Conn) error {
		var err error
		ident, history, err = readHeader(ctx, c)
		return err
	})
	if err != nil {
		return err
	}
	if ident.tenantID != t.id.String() {
		return fmt.Errorf("%w: the file identifies a different tenant", ErrForeignFile)
	}
	// Refusals come before the keys are used and before anything is written.
	action, err := s.migrations.decide(ident, history)
	if err != nil {
		return err
	}
	master, err := s.keys.Generation(ctx, ident.generation)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyMismatch, err)
	}
	kek, err := deriveKEK(master, t.id)
	if err != nil {
		return err
	}
	defer clear(kek)
	dataKey, err := unwrapKey(kek, ident.wrappedData, t.id, ident.generation, purposeData)
	if err != nil {
		return err
	}
	idKey, err := unwrapKey(kek, ident.wrappedID, t.id, ident.generation, purposeStableID)
	if err != nil {
		clear(dataKey)
		return err
	}
	t.setKeys(dataKey, idKey)
	if action == migrateForward {
		return s.migrate(ctx, t, f.dir, ident)
	}
	return nil
}

// Acquire returns the open tenant id, opening it if needed, and a function
// that must be called to release it. When MaxOpen tenants are open and all are
// held, Acquire waits for a release, but never forever: if ctx has no
// deadline it gives up after AcquireWait, and either way it then fails with
// ErrPoolExhausted. A caller that holds MaxOpen tenants and asks for another
// therefore gets an error instead of a hang.
func (s *Store) Acquire(ctx context.Context, id TenantID) (*Tenant, func(), error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.acquireWait)
		defer cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.closed {
			return nil, nil, ErrClosed
		}
		if e := s.open[id]; e != nil {
			e.refs++
			s.lru.MoveToFront(e.elem)
			return e.t, s.releaser(e), nil
		}
		if len(s.open) < s.max {
			break
		}
		if victim := s.idleLocked(); victim != nil {
			if err := s.evictLocked(victim); err != nil {
				return nil, nil, err
			}
			break
		}
		wait := s.changed
		s.mu.Unlock()
		select {
		case <-wait:
			s.mu.Lock()
		case <-ctx.Done():
			s.mu.Lock()
			return nil, nil, fmt.Errorf("%w: all %d open tenants stayed held (%w)", ErrPoolExhausted, s.max, ctx.Err())
		}
	}
	t, err := s.openTenant(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	e := &entry{t: t, refs: 1}
	e.elem = s.lru.PushFront(e)
	s.open[id] = e
	return t, s.releaser(e), nil
}

func (s *Store) releaser(e *entry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			e.refs--
			if s.closed {
				return // Close already woke every waiter
			}
			close(s.changed)
			s.changed = make(chan struct{})
		})
	}
}

// idleLocked returns the least recently used open tenant nobody holds.
func (s *Store) idleLocked() *entry {
	for el := s.lru.Back(); el != nil; el = el.Prev() {
		if e, _ := el.Value.(*entry); e != nil && e.refs == 0 {
			return e
		}
	}
	return nil
}

func (s *Store) evictLocked(e *entry) error {
	s.lru.Remove(e.elem)
	delete(s.open, e.t.id)
	return e.t.close()
}

// Delete removes tenant id from the running system: it closes the tenant and
// removes its whole directory (ADR-0010 §5), pre-migration backups included.
// It refuses while the tenant is held. The effect is immediate and complete;
// erasing the operator's own backups is a separate runbook step.
func (s *Store) Delete(_ context.Context, id TenantID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	dir, err := s.layout.dir(id)
	if err != nil {
		return err
	}
	if e := s.open[id]; e != nil {
		if e.refs > 0 {
			return ErrInUse
		}
		if err := s.evictLocked(e); err != nil {
			return err
		}
	}
	if _, err := plainDir(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("store: deleting tenant: %w", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: tenant directory still present after deletion (%w)", err)
	}
	return nil
}

// Close closes every open tenant. Tenants still held are closed too; their
// handles return ErrClosed from then on.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for _, e := range s.open {
		errs = append(errs, e.t.close())
	}
	s.open = map[TenantID]*entry{}
	s.lru.Init()
	close(s.changed)
	return errors.Join(errs...)
}
