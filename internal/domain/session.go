package domain

import "time"

// CanvasSession is one user's authorised presence on one canvas.
//
// Created from a validated canvas access token and held only in memory: a
// session is a live thing, and a restart legitimately ends every one of them.
// It is keyed separately from the user because one person may have several —
// two tabs, a phone and a laptop are distinct sessions with distinct lifetimes.
type CanvasSession struct {
	ID         string
	UserID     string
	NoteID     string
	Permission Permission

	// TokenJTI is the `jti` of the token that created or last refreshed this
	// session, so a specific token can be traced or rejected.
	TokenJTI string

	// ExpiresAt mirrors the token's expiry. A refresh extends it in place
	// rather than replacing the session, so connections survive.
	ExpiresAt time.Time

	// LastSeenAt is updated by heartbeats; an idle session is reaped.
	LastSeenAt time.Time

	CreatedAt time.Time
}

// IsExpired reports whether the underlying token has lapsed.
func (s *CanvasSession) IsExpired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// IsIdle reports whether nothing has been heard from this session for longer
// than the allowed timeout. Distinct from expiry: a session can hold a valid
// token and still have gone silent.
func (s *CanvasSession) IsIdle(now time.Time, timeout time.Duration) bool {
	return now.Sub(s.LastSeenAt) > timeout
}

// Touch records liveness.
func (s *CanvasSession) Touch(now time.Time) {
	s.LastSeenAt = now
}

// Clone returns a copy, so callers cannot mutate stored state by holding a
// pointer handed out by the store.
func (s *CanvasSession) Clone() *CanvasSession {
	clone := *s
	return &clone
}
