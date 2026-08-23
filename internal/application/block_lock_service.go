package application

import (
	"time"

	"mypol/go-realtime/internal/domain"
)

// Lock protocol events. Requests come from the client; the rest are the
// server's answers, and no client may forge them — they are stamped and emitted
// here, never relayed.
const (
	EventLockRequest = "block.lock.request"
	EventLockRenew   = "block.lock.renew"
	EventLockRelease = "block.lock.release"

	EventLockGranted  = "block.lock.granted"
	EventLockDenied   = "block.lock.denied"
	EventLockReleased = "block.lock.released"
	EventLockExpired  = "block.lock.expired"
)

// BlockLockSettings tunes the lease.
//
// The lease is short and the renew interval is well under half of it, so a
// single dropped renew does not end a gesture in progress — it takes sustained
// silence, which is the condition the expiry is actually for.
type BlockLockSettings struct {
	Lease          time.Duration
	MaxPerSession  int
	SweepThreshold time.Duration
}

// BlockLockService arbitrates geometry leases for every canvas on this node.
//
// This is the only authority. The client's optimistic gesture is a guess about
// what this service will say, and when the two disagree the client yields —
// which is why grant and denial are both answered explicitly rather than
// leaving silence to mean either.
type BlockLockService struct {
	locks    domain.LockStore
	settings BlockLockSettings
	now      Clock
}

func NewBlockLockService(locks domain.LockStore, settings BlockLockSettings, now Clock) *BlockLockService {
	if now == nil {
		now = time.Now
	}
	if settings.Lease <= 0 {
		settings.Lease = 5 * time.Second
	}
	return &BlockLockService{locks: locks, settings: settings, now: now}
}

func (s *BlockLockService) Lease() time.Duration { return s.settings.Lease }

// Request attempts to lease a block's geometry for one connection.
func (s *BlockLockService) Request(
	connection domain.Connection,
	blockID, lockID string,
) domain.AcquireOutcome {
	if blockID == "" || lockID == "" {
		return domain.AcquireOutcome{Denial: domain.DenialHeldByOther}
	}

	now := s.now()
	return s.locks.Acquire(&domain.BlockLock{
		LockID:  lockID,
		BlockID: blockID,
		// From the authenticated connection, never from the payload: a client
		// that could name the note would be able to lock blocks on a canvas it
		// has no session for.
		NoteID:       connection.NoteID(),
		ConnectionID: connection.ID(),
		SessionID:    connection.SessionID(),
		UserID:       connection.UserID(),
		AcquiredAt:   now,
		ExpiresAt:    now.Add(s.settings.Lease),
	}, s.settings.MaxPerSession, now)
}

// Renew extends a lease the caller holds.
func (s *BlockLockService) Renew(
	connection domain.Connection,
	blockID, lockID string,
) (*domain.BlockLock, error) {
	now := s.now()
	return s.locks.Renew(
		connection.NoteID(), blockID, lockID, connection.ID(),
		now.Add(s.settings.Lease), now)
}

// Release ends a lease at the end of a gesture.
func (s *BlockLockService) Release(
	connection domain.Connection,
	blockID, lockID string,
) (*domain.BlockLock, error) {
	return s.locks.Release(connection.NoteID(), blockID, lockID, connection.ID())
}

// ReleaseConnection frees everything a departing connection held.
func (s *BlockLockService) ReleaseConnection(connectionID string) []*domain.BlockLock {
	return s.locks.ReleaseAllForConnection(connectionID)
}

// SweepExpired reclaims lapsed leases.
func (s *BlockLockService) SweepExpired() []*domain.BlockLock {
	return s.locks.SweepExpired(s.now())
}

// BlockedBy reports the connection that currently owns a block's geometry, when
// it is somebody other than the caller.
//
// This is what makes the lock more than a client-side convention: a transform
// from a connection that does not hold the lease is refused at the server, so a
// client that ignores its own denial still cannot move the block.
func (s *BlockLockService) BlockedBy(
	connection domain.Connection,
	blockID string,
) (*domain.BlockLock, bool) {
	if blockID == "" {
		return nil, false
	}
	holder, ok := s.locks.Holder(connection.NoteID(), blockID, s.now())
	if !ok || holder.ConnectionID == connection.ID() {
		return nil, false
	}
	return holder, true
}

func (s *BlockLockService) ActiveLocks() int { return s.locks.Count() }

// PublicHolder is the description of a lock holder that peers are allowed to
// see: enough to render "Ana is moving this", and nothing more. Session ids and
// permissions are deliberately absent — who may edit is not other participants'
// business, and a session id is a handle to a live authorisation.
type PublicHolder struct {
	BlockID      string `json:"blockId"`
	LockID       string `json:"lockId"`
	ConnectionID string `json:"connectionId"`
	UserID       string `json:"userId"`
	ExpiresAt    int64  `json:"expiresAt"`
}

func PublicHolderOf(lock *domain.BlockLock) PublicHolder {
	return PublicHolder{
		BlockID:      lock.BlockID,
		LockID:       lock.LockID,
		ConnectionID: lock.ConnectionID,
		UserID:       lock.UserID,
		ExpiresAt:    lock.ExpiresAt.UnixMilli(),
	}
}
