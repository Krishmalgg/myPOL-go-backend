package application

import (
	"encoding/json"
	"time"

	"mypol/go-realtime/internal/domain"
)

// Server-generated presence events. Clients never emit these: only the server
// knows who is genuinely attached, so letting a client claim a join or a leave
// would make presence a matter of opinion.
const (
	EventRoomMembers    = "room.members"
	EventPresenceJoined = "presence.joined"
	EventPresenceLeft   = "presence.left"
)

// RoomStore is the port for live room membership.
type RoomStore interface {
	Join(connection domain.Connection) int
	Leave(connection domain.Connection) int
	Peers(noteID, exceptConnectionID string) []domain.Connection
	Members(noteID string) []domain.Connection
	ConnectionsForSession(sessionID string) []domain.Connection
	ConnectionsForUserOnNote(noteID, userID string) []domain.Connection
	RoomCount() int
	ConnectionCount() int
}

// MessageIDFunc mints envelope ids for server-generated messages.
type MessageIDFunc func() string

// RoomService owns membership, presence and relay for canvas rooms.
//
// The relay deliberately does no interest filtering yet — everyone on a note
// receives everything. That is the known scaling bottleneck and is addressed in
// a later phase; wiring it in now would mean building spatial indexing before
// there is any traffic to measure it against.
type RoomService struct {
	rooms     RoomStore
	newID     MessageIDFunc
	now       Clock
	channelOf func(noteID string) string
}

func NewRoomService(rooms RoomStore, newID MessageIDFunc, now Clock) *RoomService {
	if now == nil {
		now = time.Now
	}
	return &RoomService{
		rooms: rooms,
		newID: newID,
		now:   now,
		channelOf: func(noteID string) string {
			return "note:" + noteID
		},
	}
}

// Join attaches a connection, tells it who is already present, and announces it
// to everyone else.
//
// The order matters: the newcomer gets the roster before the room hears about
// them, so nobody can receive a `presence.joined` for someone who is not yet in
// the roster they were handed.
func (s *RoomService) Join(connection domain.Connection) {
	s.rooms.Join(connection)

	members := make([]domain.Member, 0)
	for _, peer := range s.rooms.Members(connection.NoteID()) {
		members = append(members, domain.MemberOf(peer))
	}
	_ = connection.SendReliable(s.envelope(connection.NoteID(), EventRoomMembers, map[string]any{
		"members": members,
	}))

	s.broadcastReliable(connection.NoteID(), connection.ID(), EventPresenceJoined, map[string]any{
		"member": domain.MemberOf(connection),
	})
}

// Leave detaches a connection and announces its departure.
func (s *RoomService) Leave(connection domain.Connection) {
	s.rooms.Leave(connection)

	s.broadcastReliable(connection.NoteID(), connection.ID(), EventPresenceLeft, map[string]any{
		"connectionId": connection.ID(),
		"userId":       connection.UserID(),
		"sessionId":    connection.SessionID(),
	})
}

// Relay forwards a client message to the rest of the room.
//
// Ephemeral traffic is coalesced per stream so a slow reader sheds stale frames
// instead of accumulating a backlog; reliable traffic is queued and a full
// queue closes the connection rather than dropping final state on the floor.
func (s *RoomService) Relay(sender domain.Connection, envelope *domain.Envelope) {
	class := domain.ClassifyEvent(envelope.Event)
	peers := s.rooms.Peers(sender.NoteID(), sender.ID())

	for _, peer := range peers {
		if class == domain.ClassEphemeral {
			peer.SendEphemeral(envelope, coalesceKey(sender.ID(), envelope))
			continue
		}
		if err := peer.SendReliable(envelope); err != nil {
			// The peer cannot keep up with traffic it is not allowed to lose.
			// Closing is the honest outcome: it will reconnect and resync.
			peer.Close("reliable queue overflow")
		}
	}
}

// DisconnectSession drops every connection bound to a revoked session.
func (s *RoomService) DisconnectSession(sessionID, reason string) int {
	connections := s.rooms.ConnectionsForSession(sessionID)
	for _, connection := range connections {
		connection.Close(reason)
	}
	return len(connections)
}

// DisconnectUserFromNote drops a user's connections on one note, across tabs.
func (s *RoomService) DisconnectUserFromNote(noteID, userID, reason string) int {
	connections := s.rooms.ConnectionsForUserOnNote(noteID, userID)
	for _, connection := range connections {
		connection.Close(reason)
	}
	return len(connections)
}

// ApplyPermission updates live connections for a session in place, so a
// demotion takes effect without dropping the socket.
func (s *RoomService) ApplyPermission(sessionID string, permission domain.Permission) int {
	connections := s.rooms.ConnectionsForSession(sessionID)
	for _, connection := range connections {
		connection.SetPermission(permission)
	}
	return len(connections)
}

func (s *RoomService) RoomCount() int       { return s.rooms.RoomCount() }
func (s *RoomService) ConnectionCount() int { return s.rooms.ConnectionCount() }

// ── internals ───────────────────────────────────────────────────────────────

func (s *RoomService) broadcastReliable(noteID, exceptConnectionID, event string, payload any) {
	envelope := s.envelope(noteID, event, payload)
	for _, peer := range s.rooms.Peers(noteID, exceptConnectionID) {
		if err := peer.SendReliable(envelope); err != nil {
			peer.Close("reliable queue overflow")
		}
	}
}

func (s *RoomService) envelope(noteID, event string, payload any) *domain.Envelope {
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte("null")
	}
	return &domain.Envelope{
		V:         domain.EnvelopeVersion,
		MessageID: s.newID(),
		Channel:   s.channelOf(noteID),
		Event:     event,
		SentAt:    s.now().UnixMilli(),
		Payload:   encoded,
	}
}

// coalesceKey groups frames that supersede one another. Two strokes from the
// same author are independent streams, so the subject id is part of the key —
// otherwise a second stroke would evict the first mid-draw.
func coalesceKey(connectionID string, envelope *domain.Envelope) string {
	return connectionID + "|" + envelope.Event + "|" + subjectID(envelope.Payload)
}

func subjectID(payload json.RawMessage) string {
	var fields struct {
		StrokeID string `json:"strokeId"`
		BlockID  string `json:"blockId"`
		PageID   string `json:"pageId"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return ""
	}
	switch {
	case fields.StrokeID != "":
		return fields.StrokeID
	case fields.BlockID != "":
		return fields.BlockID
	default:
		return fields.PageID
	}
}
