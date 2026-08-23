package domain

import (
	"errors"
	"time"
)

var (
	ErrLockNotHeld  = errors.New("lock not held by this connection")
	ErrLockNotFound = errors.New("lock not found")
)

// BlockLock is a short lease on one block's *geometry*.
//
// Deliberately not a content lock. It exists so two people dragging the same
// image do not fight over its position, and for nothing else: text inside a
// block, ink on a drawing and everything else stay editable by anyone with
// permission while this is held. Making it broader would turn a five-second
// courtesy into a way to hold a block hostage.
//
// The lease is short and renewed by the holder rather than released by a
// promise, because the failure that matters is a browser tab vanishing
// mid-drag. A lock that has to be released cleanly would strand the block; a
// lock that expires on its own recovers with no participation from the client
// that died.
type BlockLock struct {
	// LockID identifies this grant. A renew or release naming a stale id is
	// refused, so a client that reconnects cannot resurrect a lease the server
	// already expired and handed to somebody else.
	LockID string

	BlockID string
	NoteID  string

	// Held per connection, not per user: the same person in two tabs is two
	// independent grabbers, and the second one must lose exactly as a stranger
	// would.
	ConnectionID string
	SessionID    string
	UserID       string

	AcquiredAt time.Time
	ExpiresAt  time.Time
}

func (l *BlockLock) IsExpired(now time.Time) bool {
	return !now.Before(l.ExpiresAt)
}

func (l *BlockLock) Clone() *BlockLock {
	clone := *l
	return &clone
}

// LockDenial explains a refusal, so the client can tell "someone else has it"
// from "you are holding too many" and react differently to each.
type LockDenial string

const (
	// DenialHeldByOther is the ordinary case: another live connection has it.
	DenialHeldByOther LockDenial = "held-by-other"
	// DenialTooManyLocks bounds how much of a canvas one session can pin at
	// once, so a buggy or hostile client cannot lease every block in the room.
	DenialTooManyLocks LockDenial = "too-many-locks"
)

// AcquireOutcome is the result of a lock attempt.
//
// Holder is populated only on DenialHeldByOther, and only with what the UI
// legitimately needs to say "Ana is moving this" — never the holder's token,
// permission or session internals.
type AcquireOutcome struct {
	Lock   *BlockLock
	Holder *BlockLock
	Denial LockDenial
}

func (o AcquireOutcome) Granted() bool { return o.Denial == "" && o.Lock != nil }

// LockStore holds live geometry leases.
//
// Every mutation is expressed as one call rather than a read followed by a
// write, because two clients grabbing the same block at the same instant is the
// normal case, not the edge case. Splitting check from set would make the race
// reachable from the application layer.
type LockStore interface {
	// Acquire grants a lease, or reports why it could not. maxPerSession is
	// applied inside the same critical section as the grant, so a client
	// spraying requests cannot slip past the ceiling.
	Acquire(lock *BlockLock, maxPerSession int, now time.Time) AcquireOutcome

	// Renew extends a lease the caller already holds. Refusing an unknown or
	// foreign lockId is what stops a late renew from stealing back a lease that
	// expired and was regranted.
	Renew(noteID, blockID, lockID, connectionID string, expiresAt time.Time, now time.Time) (*BlockLock, error)

	// Release ends a lease early — the ordinary end of a gesture.
	Release(noteID, blockID, lockID, connectionID string) (*BlockLock, error)

	// ReleaseAllForConnection drops everything a dropped connection held, which
	// is the path that actually matters: a closed tab must not pin a block.
	ReleaseAllForConnection(connectionID string) []*BlockLock

	// SweepExpired removes lapsed leases and returns them, so the room can be
	// told the block is free again.
	SweepExpired(now time.Time) []*BlockLock

	// Holder reports the live lease on a block, if any.
	Holder(noteID, blockID string, now time.Time) (*BlockLock, bool)

	Count() int
}
