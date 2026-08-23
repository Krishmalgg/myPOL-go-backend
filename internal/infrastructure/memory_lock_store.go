package infrastructure

import (
	"sync"
	"time"

	"mypol/go-realtime/internal/domain"
)

// MemoryLockStore holds live block geometry leases.
//
// Keyed by note and block, because a lock is meaningful only inside the canvas
// it belongs to: two notes may hold blocks with the same id after a copy, and
// they must not contend.
//
// A plain mutex, like the other stores: every interesting operation writes, and
// the critical sections are a map lookup long.
type MemoryLockStore struct {
	mu sync.Mutex
	// locks[noteID][blockID]
	locks map[string]map[string]*domain.BlockLock
	// perSession counts live leases so the ceiling can be enforced without
	// walking every note on each request.
	perSession map[string]int
}

func NewMemoryLockStore() *MemoryLockStore {
	return &MemoryLockStore{
		locks:      make(map[string]map[string]*domain.BlockLock),
		perSession: make(map[string]int),
	}
}

// Acquire grants a lease when the block is free, expired, or already this
// connection's.
//
// Re-granting to the existing holder rather than refusing matters: a gesture
// that briefly outlives its lease, or a request that crossed a renew in flight,
// should continue rather than snap the block away from the person dragging it.
func (s *MemoryLockStore) Acquire(
	lock *domain.BlockLock,
	maxPerSession int,
	now time.Time,
) domain.AcquireOutcome {
	if lock == nil {
		return domain.AcquireOutcome{Denial: domain.DenialHeldByOther}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	blocks, ok := s.locks[lock.NoteID]
	if !ok {
		blocks = make(map[string]*domain.BlockLock)
		s.locks[lock.NoteID] = blocks
	}

	existing, held := blocks[lock.BlockID]
	reacquiring := held && existing.ConnectionID == lock.ConnectionID

	if held && !reacquiring && !existing.IsExpired(now) {
		return domain.AcquireOutcome{
			Holder: existing.Clone(),
			Denial: domain.DenialHeldByOther,
		}
	}

	// The ceiling applies to new leases only. Refusing to re-grant one the
	// caller already holds would be self-defeating — it would push them over
	// the limit and then punish them for it.
	if !reacquiring && maxPerSession > 0 && s.perSession[lock.SessionID] >= maxPerSession {
		return domain.AcquireOutcome{Denial: domain.DenialTooManyLocks}
	}

	if held {
		s.decrementLocked(existing.SessionID)
	}

	stored := lock.Clone()
	blocks[lock.BlockID] = stored
	s.perSession[stored.SessionID]++

	return domain.AcquireOutcome{Lock: stored.Clone()}
}

func (s *MemoryLockStore) Renew(
	noteID, blockID, lockID, connectionID string,
	expiresAt time.Time,
	now time.Time,
) (*domain.BlockLock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.locks[noteID][blockID]
	if !ok {
		return nil, domain.ErrLockNotFound
	}
	// An expired lease is not renewable even by its own holder. Allowing it
	// would make the expiry advisory, and the room has already been told the
	// block is free.
	if existing.IsExpired(now) {
		return nil, domain.ErrLockNotFound
	}
	if existing.LockID != lockID || existing.ConnectionID != connectionID {
		return nil, domain.ErrLockNotHeld
	}

	existing.ExpiresAt = expiresAt
	return existing.Clone(), nil
}

func (s *MemoryLockStore) Release(
	noteID, blockID, lockID, connectionID string,
) (*domain.BlockLock, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	blocks, ok := s.locks[noteID]
	if !ok {
		return nil, domain.ErrLockNotFound
	}
	existing, ok := blocks[blockID]
	if !ok {
		return nil, domain.ErrLockNotFound
	}
	if existing.LockID != lockID || existing.ConnectionID != connectionID {
		return nil, domain.ErrLockNotHeld
	}

	s.removeLocked(noteID, blockID, existing)
	return existing.Clone(), nil
}

// ReleaseAllForConnection is the disconnect path: a vanished tab must not keep
// a block pinned until its lease happens to lapse.
func (s *MemoryLockStore) ReleaseAllForConnection(connectionID string) []*domain.BlockLock {
	s.mu.Lock()
	defer s.mu.Unlock()

	released := make([]*domain.BlockLock, 0)
	for noteID, blocks := range s.locks {
		for blockID, lock := range blocks {
			if lock.ConnectionID != connectionID {
				continue
			}
			released = append(released, lock.Clone())
			s.removeLocked(noteID, blockID, lock)
		}
	}
	return released
}

func (s *MemoryLockStore) SweepExpired(now time.Time) []*domain.BlockLock {
	s.mu.Lock()
	defer s.mu.Unlock()

	expired := make([]*domain.BlockLock, 0)
	for noteID, blocks := range s.locks {
		for blockID, lock := range blocks {
			if !lock.IsExpired(now) {
				continue
			}
			expired = append(expired, lock.Clone())
			s.removeLocked(noteID, blockID, lock)
		}
	}
	return expired
}

func (s *MemoryLockStore) Holder(noteID, blockID string, now time.Time) (*domain.BlockLock, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, ok := s.locks[noteID][blockID]
	if !ok || lock.IsExpired(now) {
		return nil, false
	}
	return lock.Clone(), true
}

func (s *MemoryLockStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for _, blocks := range s.locks {
		total += len(blocks)
	}
	return total
}

// ── internals, all called with the mutex held ───────────────────────────────

func (s *MemoryLockStore) removeLocked(noteID, blockID string, lock *domain.BlockLock) {
	delete(s.locks[noteID], blockID)
	if len(s.locks[noteID]) == 0 {
		delete(s.locks, noteID)
	}
	s.decrementLocked(lock.SessionID)
}

func (s *MemoryLockStore) decrementLocked(sessionID string) {
	if s.perSession[sessionID] <= 1 {
		delete(s.perSession, sessionID)
		return
	}
	s.perSession[sessionID]--
}
