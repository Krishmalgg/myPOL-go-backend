package domain

import "time"

// ConnectionTicket is a single-use credential for opening a realtime transport.
//
// It exists because a browser cannot set headers on a WebSocket handshake, and
// putting a JWT in a URL is worse than it looks: query strings land in proxy
// logs, browser history and Referer headers. A ticket is short-lived, single-use
// and useless once redeemed, so leaking one costs far less than leaking a token.
//
// It carries a snapshot of the authorisation rather than a pointer to it, so the
// connection handler can bind a connection without re-reading the session.
type ConnectionTicket struct {
	// Value is the opaque secret presented at connect time.
	Value string

	SessionID  string
	UserID     string
	NoteID     string
	Permission Permission

	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the ticket may still be redeemed.
func (t *ConnectionTicket) IsExpired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

// Clone returns a copy so stored state cannot be mutated through a handed-out
// pointer.
func (t *ConnectionTicket) Clone() *ConnectionTicket {
	clone := *t
	return &clone
}
