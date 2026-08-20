package domain

import (
	"errors"
	"time"
)

var (
	ErrSessionNotFound   = errors.New("session not found")
	ErrTicketNotFound    = errors.New("ticket not found")
	ErrTicketExpired     = errors.New("ticket expired")
	ErrInvalidPermission = errors.New("invalid permission")
)

// SessionStore holds live canvas sessions.
//
// Phase 1 is a single instance with in-memory state, which is why this is an
// interface: swapping in a Redis-backed store for horizontal scaling must not
// touch the application layer.
type SessionStore interface {
	Save(session *CanvasSession) error
	Get(sessionID string) (*CanvasSession, bool)
	Delete(sessionID string) bool

	// DeleteByUserAndNote removes every session a user holds on a note and
	// returns how many were removed — the "revoke this person now" path, which
	// must catch all their tabs and devices.
	DeleteByUserAndNote(userID, noteID string) int

	// UpdatePermission changes what a live session may do without ending it, so
	// an editor can be demoted to a viewer in place.
	UpdatePermission(sessionID string, permission Permission) error

	Touch(sessionID string, now time.Time) error

	// SweepExpired removes sessions whose token lapsed or which went silent.
	SweepExpired(now time.Time, idleTimeout time.Duration) int

	Count() int
}

// TicketStore holds unredeemed connection tickets.
type TicketStore interface {
	Issue(ticket *ConnectionTicket) error

	// Consume redeems a ticket, removing it in the same atomic step. A second
	// attempt with the same value must fail — that is what makes it single-use,
	// and it has to be enforced here rather than by the caller, because two
	// connections can race for one ticket.
	Consume(value string, now time.Time) (*ConnectionTicket, error)

	// SweepExpired drops unredeemed tickets past their TTL, so the store cannot
	// grow without bound from abandoned bootstraps.
	SweepExpired(now time.Time) int

	// DeleteBySession revokes outstanding tickets when their session ends.
	DeleteBySession(sessionID string) int

	Count() int
}
