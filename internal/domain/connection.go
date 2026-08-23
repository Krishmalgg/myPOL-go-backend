package domain

import "time"

// Connection is one live transport attached to a canvas room.
//
// Kept as an interface so rooms and presence never learn which transport is
// underneath. A WebSocket implements it today; WebTransport will implement the
// same contract without the room layer changing.
//
// A user may hold several connections at once — two tabs, a phone and a laptop
// — so identity here is per connection, not per user.
type Connection interface {
	ID() string
	SessionID() string
	UserID() string
	NoteID() string

	// Permission may change mid-connection when .NET demotes a session in
	// place, so it is read through a method rather than captured once.
	Permission() Permission
	SetPermission(Permission)

	// SendReliable queues a message that must arrive. It returns an error when
	// the queue is full — the caller must not silently discard the message.
	SendReliable(envelope *Envelope) error

	// SendEphemeral queues a droppable message. Frames sharing a coalesce key
	// replace each other, so a slow reader costs one frame per stream rather
	// than a backlog of every frame produced while it was slow.
	SendEphemeral(envelope *Envelope, coalesceKey string)

	// Close ends the connection with a reason for logging.
	Close(reason string)

	// PendingReliable reports frames accepted by the bounded reliable queue but
	// not yet handed to the transport writer. It lets a draining server give
	// final/control traffic a short chance to leave before it closes sessions.
	PendingReliable() int

	ConnectedAt() time.Time
}

// Member is the public description of someone in a room, as broadcast in
// presence events. Deliberately minimal: no permission, because who may edit is
// not other participants' business.
type Member struct {
	ConnectionID string `json:"connectionId"`
	UserID       string `json:"userId"`
	SessionID    string `json:"sessionId"`
	JoinedAt     int64  `json:"joinedAt"`
}

// MemberOf describes a connection for presence purposes.
func MemberOf(connection Connection) Member {
	return Member{
		ConnectionID: connection.ID(),
		UserID:       connection.UserID(),
		SessionID:    connection.SessionID(),
		JoinedAt:     connection.ConnectedAt().UnixMilli(),
	}
}
