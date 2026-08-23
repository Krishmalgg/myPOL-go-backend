package application

import (
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
)

type movableClock struct{ at time.Time }

func (c *movableClock) now() time.Time          { return c.at }
func (c *movableClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newLocks(maxPerSession int) (*BlockLockService, *movableClock) {
	clock := &movableClock{at: time.Unix(1000, 0)}
	service := NewBlockLockService(
		infrastructure.NewMemoryLockStore(),
		BlockLockSettings{Lease: 5 * time.Second, MaxPerSession: maxPerSession},
		clock.now,
	)
	return service, clock
}

func TestFirstRequestWins(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	if !locks.Request(ana, "block-1", "lock-a").Granted() {
		t.Fatal("the first request should be granted")
	}

	outcome := locks.Request(ben, "block-1", "lock-b")
	if outcome.Granted() {
		t.Fatal("a held block must not be granted twice")
	}
	if outcome.Denial != domain.DenialHeldByOther {
		t.Errorf("denial = %q, want held-by-other", outcome.Denial)
	}
	// The UI has to be able to say *who*, or the block just stops working with
	// no explanation.
	if outcome.Holder == nil || outcome.Holder.UserID != "user-ana" {
		t.Error("a denial should name the holder")
	}
}

// Two tabs belonging to one person are two grabbers, and the second must lose
// exactly as a stranger would — otherwise a stale tab could steal a block out
// from under the window its owner is actually using.
func TestASecondTabIsTreatedAsAStranger(t *testing.T) {
	locks, _ := newLocks(4)
	tabOne := newFakeConnection("conn-1", "sess-1", "user-ana", "note-1")
	tabTwo := newFakeConnection("conn-2", "sess-2", "user-ana", "note-1")

	locks.Request(tabOne, "block-1", "lock-a")

	if locks.Request(tabTwo, "block-1", "lock-b").Granted() {
		t.Fatal("the same user's other connection must not take the lock")
	}
}

// A request that crossed a renew in flight, or a gesture that briefly outlived
// its lease, should continue rather than snapping the block away from the
// person who is visibly dragging it.
func TestTheHolderMayReacquireItsOwnLock(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	locks.Request(ana, "block-1", "lock-a")
	if !locks.Request(ana, "block-1", "lock-a2").Granted() {
		t.Fatal("the holder should be able to re-acquire")
	}
}

func TestAnExpiredLeaseIsUpForGrabs(t *testing.T) {
	locks, clock := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	locks.Request(ana, "block-1", "lock-a")
	clock.advance(6 * time.Second)

	if !locks.Request(ben, "block-1", "lock-b").Granted() {
		t.Fatal("a lapsed lease must not keep a block pinned")
	}
}

func TestRenewExtendsTheLease(t *testing.T) {
	locks, clock := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	locks.Request(ana, "block-1", "lock-a")

	clock.advance(4 * time.Second)
	if _, err := locks.Renew(ana, "block-1", "lock-a"); err != nil {
		t.Fatalf("renew failed: %v", err)
	}

	// Past the original expiry, but inside the renewed one.
	clock.advance(3 * time.Second)
	if locks.Request(ben, "block-1", "lock-b").Granted() {
		t.Fatal("a renewed lease should still hold")
	}
}

// The lockId is what stops a client that reconnects from resurrecting a lease
// the server already expired and handed to somebody else.
func TestRenewingWithAStaleLockIDIsRefused(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	locks.Request(ana, "block-1", "lock-a")

	if _, err := locks.Renew(ana, "block-1", "some-other-lock"); err == nil {
		t.Fatal("a foreign lockId must not renew a lease")
	}
}

func TestOnlyTheHolderMayRenewOrRelease(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	granted := locks.Request(ana, "block-1", "lock-a")

	if _, err := locks.Renew(ben, "block-1", granted.Lock.LockID); err == nil {
		t.Error("another connection must not renew someone else's lease")
	}
	if _, err := locks.Release(ben, "block-1", granted.Lock.LockID); err == nil {
		t.Error("another connection must not release someone else's lease")
	}
}

func TestReleaseFreesTheBlock(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	locks.Request(ana, "block-1", "lock-a")
	if _, err := locks.Release(ana, "block-1", "lock-a"); err != nil {
		t.Fatalf("release failed: %v", err)
	}

	if !locks.Request(ben, "block-1", "lock-b").Granted() {
		t.Fatal("a released block should be available")
	}
}

// The ceiling exists so a buggy or hostile client cannot lease every block on
// the canvas and quietly freeze the room.
func TestASessionCannotHoldMoreThanTheCeiling(t *testing.T) {
	locks, _ := newLocks(2)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	locks.Request(ana, "block-1", "lock-1")
	locks.Request(ana, "block-2", "lock-2")

	outcome := locks.Request(ana, "block-3", "lock-3")
	if outcome.Granted() {
		t.Fatal("the ceiling should have stopped the third lock")
	}
	if outcome.Denial != domain.DenialTooManyLocks {
		t.Errorf("denial = %q, want too-many-locks", outcome.Denial)
	}
}

// Refusing to re-grant a lock the caller already holds would push them over the
// ceiling and then punish them for it.
func TestTheCeilingDoesNotBlockReacquiringAHeldLock(t *testing.T) {
	locks, _ := newLocks(1)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	locks.Request(ana, "block-1", "lock-1")

	if !locks.Request(ana, "block-1", "lock-1b").Granted() {
		t.Fatal("re-acquiring a held lock must not count against the ceiling")
	}
}

// The case the whole lease design exists for: a tab that vanishes never sends a
// release.
func TestDisconnectReleasesEverythingAConnectionHeld(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	locks.Request(ana, "block-1", "lock-1")
	locks.Request(ana, "block-2", "lock-2")

	released := locks.ReleaseConnection("conn-ana")
	if len(released) != 2 {
		t.Fatalf("released %d locks, want 2", len(released))
	}
	if !locks.Request(ben, "block-1", "lock-b").Granted() {
		t.Fatal("a dropped connection must not keep a block pinned")
	}
}

func TestSweepReturnsLapsedLeasesSoTheRoomCanBeTold(t *testing.T) {
	locks, clock := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	locks.Request(ana, "block-1", "lock-1")
	if len(locks.SweepExpired()) != 0 {
		t.Fatal("a live lease must not be swept")
	}

	clock.advance(6 * time.Second)
	expired := locks.SweepExpired()

	if len(expired) != 1 || expired[0].BlockID != "block-1" {
		t.Fatalf("sweep returned %d locks, want the lapsed one", len(expired))
	}
	if locks.ActiveLocks() != 0 {
		t.Errorf("active locks = %d, want 0", locks.ActiveLocks())
	}
}

// This is what makes the lease more than a client-side convention.
func TestBlockedByNamesTheHolderForEveryoneElse(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-1")

	locks.Request(ana, "block-1", "lock-1")

	if _, blocked := locks.BlockedBy(ana, "block-1"); blocked {
		t.Error("the holder is not blocked by its own lease")
	}
	holder, blocked := locks.BlockedBy(ben, "block-1")
	if !blocked || holder.UserID != "user-ana" {
		t.Error("a non-holder should be blocked and told who holds it")
	}
	if _, blocked := locks.BlockedBy(ben, "block-2"); blocked {
		t.Error("an unlocked block blocks nobody")
	}
}

// A lock is meaningful only inside the canvas it belongs to: two notes may hold
// blocks with the same id after a copy, and they must not contend.
func TestLocksAreScopedToTheirNote(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")
	ben := newFakeConnection("conn-ben", "sess-ben", "user-ben", "note-2")

	locks.Request(ana, "block-1", "lock-1")

	if !locks.Request(ben, "block-1", "lock-2").Granted() {
		t.Fatal("the same block id on another note must not contend")
	}
}

// Peers get enough to render "Ana is moving this" and nothing that would let
// them act as her.
func TestThePublicHolderShapeLeaksNothingSensitive(t *testing.T) {
	locks, _ := newLocks(4)
	ana := newFakeConnection("conn-ana", "sess-ana", "user-ana", "note-1")

	granted := locks.Request(ana, "block-1", "lock-1")
	public := PublicHolderOf(granted.Lock)

	if public.UserID != "user-ana" || public.ConnectionID != "conn-ana" {
		t.Error("the holder should be identifiable")
	}
	if public.ExpiresAt == 0 {
		t.Error("peers need the expiry to know when to stop waiting")
	}
}
