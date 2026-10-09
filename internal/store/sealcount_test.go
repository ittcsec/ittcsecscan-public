package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/ittcsec/ittcsecscan/internal/repo"
)

// smallLimitStore opens a store whose data key is exhausted after hardStop
// encryptions, so a test can actually reach the limit. warn sits one slot
// below the stop. The fixture's first scan is counted now (B-6 covers the
// initial load), so the counter is reset afterwards, leaving hardStop slots for
// the test to reason about from a known zero.
func smallLimitStore(t *testing.T, hardStop int64) (*Store, *Tenant, int64) {
	t.Helper()
	s, _ := newTestStore(t, func(o *Options) {
		o.sealHardStop = hardStop
		o.sealWarn = hardStop - 1
	})
	tn := acquire(t, s, createTenant(t, s))
	loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})
	resetSealCount(t, tn)
	return s, tn, readFixture(t, tn)[0].node
}

// resetSealCount clears the data-key encryption counter. The fixtures' first
// scan draws from it, so a test that needs the reservation arithmetic to start
// from zero resets it after the fixture is in place. It is a deliberate,
// test-only reach past the never-decrement rule, to isolate the counter from
// the scaffolding.
func resetSealCount(t *testing.T, tn *Tenant) {
	t.Helper()
	err := tn.withConn(context.Background(), func(c *sql.Conn) error {
		_, e := c.ExecContext(context.Background(), "UPDATE tenant SET data_key_seal_count = 0")
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sealCountNow(t *testing.T, tn *Tenant) int64 {
	t.Helper()
	n, err := tn.sealCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A seal-then-rollback attack cannot drive more encryptions under a data key
// than the hard stop, however many times it rolls back (B-6). This is the
// genuine attack, not a value check: each iteration performs a real encryption
// inside an Update and then forces that Update to roll back, exactly the way a
// transactional counter would be evaded, and the loop tries to run well past
// the limit. The reservation — committed in its own transaction before the
// Update — is what a rollback cannot undo, so the committed count climbs on
// every attempt and the attack is refused the moment it reaches the stop.
func TestSealCountResistsSealRollbackAttack(t *testing.T) {
	ctx := context.Background()
	const hardStop = 8
	_, tn, row := smallLimitStore(t, hardStop)

	// The attacker's forced-rollback marker; distinct from ErrKeyExhausted so
	// the loop can tell a rolled-back seal from a refused reservation.
	errRollback := errors.New("attacker rolls back")

	seals := 0
	var stopped error
	for i := 0; i < hardStop*4; i++ {
		// Step 1: reserve one slot. This commits count += 1 in its own
		// transaction. The attacker has to do this to get a slot at all, and it
		// is the step a later rollback cannot reach.
		res, err := tn.reserveSeals(ctx, 1)
		if err != nil {
			stopped = err
			break
		}
		// Step 2: perform a real encryption inside an Update, then roll the
		// Update back, hoping the encryption "did not count".
		var sealed []byte
		attack := tn.Update(ctx, func(repo.Writer) error {
			var e error
			sealed, e = tn.SealCounted(res, FieldEntityTags(), row, []byte("secret"))
			if e != nil {
				return e
			}
			return errRollback
		})
		if !errors.Is(attack, errRollback) {
			t.Fatalf("iteration %d: Update returned %v, want the forced rollback", i, attack)
		}
		// The encryption really happened: the ciphertext exists and decrypts.
		// A no-op loop would prove nothing about the limit.
		pt, err := tn.OpenValue(FieldEntityTags(), row, sealed)
		if err != nil || string(pt) != "secret" {
			t.Fatalf("iteration %d: seal was not a real encryption: pt=%q err=%v", i, pt, err)
		}
		seals++
	}

	// The attack was stopped, and stopped by the encryption limit — not by the
	// loop running out of iterations.
	if !errors.Is(stopped, ErrKeyExhausted) {
		t.Fatalf("the reservation limit did not stop the attack: err = %v", stopped)
	}
	if seals != hardStop {
		t.Errorf("attacker performed %d real encryptions past %d rollbacks; the hard stop was %d", seals, hardStop*4, hardStop)
	}
	// Every rollback left the committed count exactly where the reservations put
	// it: at the stop, never lowered.
	if got := sealCountNow(t, tn); got != hardStop {
		t.Errorf("committed count = %d after the attack, want the hard stop %d", got, hardStop)
	}
	// And the door stays shut: a fresh reservation is still refused.
	if _, err := tn.reserveSeals(ctx, 1); !errors.Is(err, ErrKeyExhausted) {
		t.Errorf("after the attack, reserveSeals = %v, want ErrKeyExhausted", err)
	}
}

// reserveSeals refuses a claim that would pass the hard stop and changes
// nothing, so the count never rises above the limit even by one slot.
func TestReserveSealsRefusesPastHardStop(t *testing.T) {
	ctx := context.Background()
	const hardStop = 10
	_, tn, _ := smallLimitStore(t, hardStop)

	// Reserve up to one below the stop; that must succeed.
	if _, err := tn.reserveSeals(ctx, hardStop-1); err != nil {
		t.Fatalf("reserving %d of %d slots: %v", hardStop-1, hardStop, err)
	}
	if got := sealCountNow(t, tn); got != hardStop-1 {
		t.Fatalf("count = %d after reserving %d, want %d", got, hardStop-1, hardStop-1)
	}
	// Reserving two more would cross the stop: refused, and nothing committed.
	if _, err := tn.reserveSeals(ctx, 2); !errors.Is(err, ErrKeyExhausted) {
		t.Errorf("over-reservation = %v, want ErrKeyExhausted", err)
	}
	if got := sealCountNow(t, tn); got != hardStop-1 {
		t.Errorf("a refused reservation changed the count to %d, want %d", got, hardStop-1)
	}
	// The last slot still reserves, exactly to the stop.
	if _, err := tn.reserveSeals(ctx, 1); err != nil {
		t.Errorf("reserving the final slot: %v", err)
	}
	if got := sealCountNow(t, tn); got != hardStop {
		t.Errorf("count = %d after reserving the last slot, want %d", got, hardStop)
	}
}

// The other direction of the rollback guarantee: a committed reservation is not
// lost when a later Update rolls back. The count that should be there stays.
func TestReserveSurvivesRolledBackUpdate(t *testing.T) {
	ctx := context.Background()
	_, tn, row := smallLimitStore(t, 1<<20)

	res, err := tn.reserveSeals(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	before := sealCountNow(t, tn)

	errBoom := errors.New("boom")
	err = tn.Update(ctx, func(repo.Writer) error {
		if _, err := tn.SealCounted(res, FieldEntityTags(), row, []byte("x")); err != nil {
			return err
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Update = %v, want boom", err)
	}
	if got := sealCountNow(t, tn); got != before {
		t.Errorf("committed count changed from %d to %d across a rolled-back Update", before, got)
	}
}

// SealCounted refuses, before encrypting, once its reservation is spent or when
// it has none: a caller cannot seal more values than it reserved.
func TestSealCountedNeedsAReservation(t *testing.T) {
	ctx := context.Background()
	_, tn, row := smallLimitStore(t, 1<<20)

	if _, err := tn.SealCounted(nil, FieldEntityTags(), row, []byte("x")); !errors.Is(err, ErrKeyExhausted) {
		t.Errorf("SealCounted(nil) = %v, want ErrKeyExhausted", err)
	}

	res, err := tn.reserveSeals(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tn.SealCounted(res, FieldEntityTags(), row, []byte("x")); err != nil {
		t.Fatalf("the first counted seal drew its one slot: %v", err)
	}
	// The single slot is spent; the next seal is refused before encrypting.
	if _, err := tn.SealCounted(res, FieldEntityTags(), row, []byte("y")); !errors.Is(err, ErrKeyExhausted) {
		t.Errorf("a second seal on a one-slot reservation = %v, want ErrKeyExhausted", err)
	}
}

// A reservation reports crossing the warn threshold exactly on the commit that
// reaches it, and not before or after.
func TestReserveSealsWarnThreshold(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, func(o *Options) {
		o.sealHardStop = 100
		o.sealWarn = 10
	})
	tn := acquire(t, s, createTenant(t, s))

	res, err := tn.reserveSeals(ctx, 9) // up to one below warn
	if err != nil {
		t.Fatal(err)
	}
	if res.NearLimit() {
		t.Error("reservation reported near the limit while still below the warn line")
	}
	res, err = tn.reserveSeals(ctx, 1) // reaches the warn line
	if err != nil {
		t.Fatal(err)
	}
	if !res.NearLimit() {
		t.Error("the reservation that reached the warn line did not report it")
	}
	res, err = tn.reserveSeals(ctx, 1) // already past the warn line
	if err != nil {
		t.Fatal(err)
	}
	if res.NearLimit() {
		t.Error("a reservation past the warn line reported it a second time")
	}
}

// New refuses limits that are not a positive hard stop with a lower warn.
func TestNewRejectsBadSealLimits(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hardStop, warn int64
	}{
		{"warn above stop", 10, 20},
		{"warn equals stop", 10, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Options{
				DataDir:      testDataDir(t),
				Keys:         staticKeys(t, testMasterKey(t, 1)),
				sealHardStop: tc.hardStop,
				sealWarn:     tc.warn,
			})
			if err == nil {
				t.Fatalf("New accepted hardStop=%d warn=%d", tc.hardStop, tc.warn)
			}
		})
	}
}

// The committed count is durable and never reclaimed: reserved-but-unconsumed
// slots survive a process restart (a fresh Store on the same directory) and are
// never handed back. This is what makes a crash between reserveSeals committing
// and the seals being drawn safe — it can only forfeit slots (over-count), it
// can never reuse them, which would reopen the seal-then-rollback gap (B-6).
func TestSealCountSurvivesRestartAndIsNeverReclaimed(t *testing.T) {
	ctx := context.Background()
	const hardStop = 1000
	opts := Options{
		DataDir:      testDataDir(t),
		Keys:         staticKeys(t, testMasterKey(t, 1)),
		sealHardStop: hardStop,
		sealWarn:     hardStop - 1,
	}

	// First process: reserve ten slots, draw only three, then shut down. The
	// seven undrawn slots are the ones a crash would leave behind.
	var id TenantID
	func() {
		s := openStore(t, opts)
		id = createTenant(t, s)
		tn, release, err := s.Acquire(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		loadFixture(t, tn, []fixtureEntity{{native: "arn:aws:iam::111111111111:role/app", name: "app"}})
		resetSealCount(t, tn) // start the durability check from a known zero
		row := readFixture(t, tn)[0].node

		res, err := tn.reserveSeals(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, err := tn.SealCounted(res, FieldEntityTags(), row, []byte("v")); err != nil {
				t.Fatal(err)
			}
		}
		if got := sealCountNow(t, tn); got != 10 {
			t.Fatalf("before restart: count = %d, want the 10 reserved (3 drawn, 7 not)", got)
		}
		release()
		if err := s.Close(); err != nil {
			t.Fatalf("closing the first store: %v", err)
		}
	}()

	// Second process: a brand-new Store over the same files. openStore registers
	// its own Close with t.Cleanup, so both stores never overlap.
	s2 := openStore(t, opts)
	tn2 := acquire(t, s2, id)

	// The seven undrawn slots are still counted; nothing was given back.
	if got := sealCountNow(t, tn2); got != 10 {
		t.Errorf("after restart: count = %d, want 10 (7 undrawn slots forfeited, not reclaimed)", got)
	}
	// A new reservation continues from 10, so it never re-issues a forfeited
	// slot: a `= n` (reset) or a reclaim-on-close mutation would land below 15.
	if _, err := tn2.reserveSeals(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if got := sealCountNow(t, tn2); got != 15 {
		t.Errorf("after a further reservation: count = %d, want 15 (10 + 5), proving no reuse", got)
	}
}

// Under a legitimate caller and a rollback attacker running at once, every
// reserved slot is counted exactly once, the hard stop is never passed, and
// every legitimate seal is a real, decryptable encryption (B-6). All counter
// mutations serialise on the tenant connection, so interleaving reduces to some
// sequential order; this test, run under -race in CI, proves that holds and
// that a non-atomic reserve (which would overshoot the stop or drop a count)
// does not creep in.
func TestSealCountUnderConcurrentUseAndAttack(t *testing.T) {
	ctx := context.Background()
	// The combined demand (80 attempts) is set above the hard stop (50) so the
	// limit binds while the two goroutines contend: exactly 50 reservations
	// succeed across both, the rest are refused.
	const (
		hardStop = 50
		attempts = 40 // per goroutine; 80 total
	)
	_, tn, row := smallLimitStore(t, hardStop)

	errRollback := errors.New("attacker rolls back")

	// run drives one actor: reserve one slot and seal one real value per
	// attempt, committing or rolling back per commit. It stops at the first
	// ErrKeyExhausted (from then on every reserve is refused) and returns the
	// ciphertexts of its committed seals and how many slots it drew.
	run := func(plaintext string, commit bool) (seals [][]byte, drawn int, err error) {
		for i := 0; i < attempts; i++ {
			res, rerr := tn.reserveSeals(ctx, 1)
			if errors.Is(rerr, ErrKeyExhausted) {
				return seals, drawn, nil
			}
			if rerr != nil {
				return seals, drawn, rerr
			}
			var sealed []byte
			uerr := tn.Update(ctx, func(repo.Writer) error {
				var e error
				sealed, e = tn.SealCounted(res, FieldEntityTags(), row, []byte(plaintext))
				if e != nil {
					return e
				}
				if commit {
					return nil
				}
				return errRollback
			})
			switch {
			case commit && uerr != nil:
				return seals, drawn, uerr
			case !commit && !errors.Is(uerr, errRollback):
				return seals, drawn, uerr
			}
			drawn++
			if commit {
				seals = append(seals, sealed)
			}
		}
		return seals, drawn, nil
	}

	var (
		wg                      sync.WaitGroup
		legitSeals              [][]byte
		legitDrawn, attackDrawn int
		legitErr, attackErr     error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		legitSeals, legitDrawn, legitErr = run("legit", true)
	}()
	go func() {
		defer wg.Done()
		_, attackDrawn, attackErr = run("attack", false)
	}()
	wg.Wait()

	if legitErr != nil {
		t.Fatalf("legitimate caller: %v", legitErr)
	}
	if attackErr != nil {
		t.Fatalf("attacker: %v", attackErr)
	}

	// Every slot up to the hard stop was drawn by exactly one of the two, and
	// no more: the sum is the stop, whatever order they interleaved in.
	if legitDrawn+attackDrawn != hardStop {
		t.Errorf("slots drawn = %d (%d legit + %d attack), want the hard stop %d",
			legitDrawn+attackDrawn, legitDrawn, attackDrawn, hardStop)
	}
	// The committed count equals the slots drawn and never passed the stop —
	// the attacker's rollbacks lowered nothing.
	if got := sealCountNow(t, tn); got != hardStop {
		t.Errorf("committed count = %d, want exactly the hard stop %d", got, hardStop)
	}
	// The limit actually bound during the contention (some attempts were
	// refused), so this exercised the stop, not just a comfortable margin.
	if legitDrawn == attempts && attackDrawn == attempts {
		t.Error("the hard stop never bound: both actors drew every attempt")
	}
	// Every committed legitimate seal is a real, correct encryption.
	if len(legitSeals) != legitDrawn {
		t.Fatalf("collected %d legit ciphertexts, drew %d slots", len(legitSeals), legitDrawn)
	}
	for i, sealed := range legitSeals {
		pt, err := tn.OpenValue(FieldEntityTags(), row, sealed)
		if err != nil || string(pt) != "legit" {
			t.Errorf("legit seal %d did not decrypt: pt=%q err=%v", i, pt, err)
		}
	}
}
