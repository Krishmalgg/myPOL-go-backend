package application

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
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
	ConnectionByID(noteID, connectionID string) (domain.Connection, bool)
	RoomSize(noteID string) int
	ConnectionsForSession(sessionID string) []domain.Connection
	ConnectionsForUserOnNote(noteID, userID string) []domain.Connection
	AllConnections() []domain.Connection
	RoomCount() int
	ConnectionCount() int
}

// SignalingRejection explains why a negotiation message was not delivered.
type SignalingRejection string

const (
	SignalingNoTarget     SignalingRejection = "no-target"
	SignalingTargetAbsent SignalingRejection = "target-not-in-room"
	SignalingSelfTarget   SignalingRejection = "self-target"
	SignalingRoomTooLarge SignalingRejection = "room-exceeds-peer-limit"
)

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

	// maxWebRTCPeers caps the room size in which a peer mesh is permitted.
	// Above it, signalling is refused so clients fall back to the server relay
	// rather than attempting an N² mesh.
	maxWebRTCPeers int

	// interest is optional: a nil value means every ephemeral event still
	// reaches every peer, exactly as before this existed. It is set once at
	// startup via SetInterest, the same shape as SetMaxWebRTCPeers, so every
	// existing construction site and test harness keeps working unfiltered
	// unless it opts in.
	interest *InterestService
	metrics  *observability.Metrics

	// Draining is process-wide for this room directory. It prevents existing
	// sockets from accepting application writes after readiness is withdrawn and
	// suppresses per-user departure noise while every connection is closing.
	draining atomic.Bool
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
		maxWebRTCPeers: 6,
	}
}

// SetMaxWebRTCPeers configures the mesh ceiling.
func (s *RoomService) SetMaxWebRTCPeers(limit int) {
	if limit > 0 {
		s.maxWebRTCPeers = limit
	}
}

// SetInterest turns on interest-based filtering for ephemeral relay. Metrics
// is optional; a nil value simply means recipient counts are not observed.
func (s *RoomService) SetInterest(interest *InterestService, metrics *observability.Metrics) {
	s.interest = interest
	s.metrics = metrics
}

// Join attaches a connection, tells it who is already present, and announces it
// to everyone else.
//
// The order matters: the newcomer gets the roster before the room hears about
// them, so nobody can receive a `presence.joined` for someone who is not yet in
// the roster they were handed.
func (s *RoomService) Join(connection domain.Connection) {
	// A request may have passed transport admission just before SIGTERM. Do not
	// let that narrow race create an unannounced room member after BeginDrain's
	// snapshot; closing it makes the browser use its normal reconnect path.
	if s.draining.Load() {
		connection.Close("server draining")
		return
	}

	s.rooms.Join(connection)

	members := make([]domain.Member, 0)
	for _, peer := range s.rooms.Members(connection.NoteID()) {
		members = append(members, domain.MemberOf(peer))
	}
	// `you` is how a client learns its own connection id, which it has no other
	// way to know: the id is minted here at connect time and appears in every
	// grant, presence frame and signalling target. Without it a client cannot
	// tell its own lock grant from a peer's, and would try to negotiate with
	// itself.
	_ = connection.SendReliable(s.envelope(connection.NoteID(), EventRoomMembers, map[string]any{
		"you":     connection.ID(),
		"members": members,
	}))

	s.broadcastReliable(connection.NoteID(), connection.ID(), EventPresenceJoined, map[string]any{
		"member": domain.MemberOf(connection),
	})
}

// Leave detaches a connection and announces its departure.
func (s *RoomService) Leave(connection domain.Connection) {
	s.leave(connection, !s.draining.Load())
}

// leave removes one connection, optionally suppressing the normal presence
// broadcast. A full server drain must not emit hundreds of presence.left events
// that recipients will discard while reconnecting anyway.
func (s *RoomService) leave(connection domain.Connection, announcePresence bool) {
	s.rooms.Leave(connection)
	if !announcePresence {
		return
	}

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
	if s.draining.Load() {
		return
	}
	class := domain.ClassifyEvent(envelope.Event)

	// Negotiation is addressed to one peer, never broadcast: an offer sent to a
	// whole room would have every member try to answer a negotiation that was
	// not meant for them, and would leak each peer's SDP to everyone else.
	if class == domain.ClassSignaling {
		_, _ = s.RelayToPeer(sender, envelope)
		return
	}

	peers := s.rooms.Peers(sender.NoteID(), sender.ID())

	// Interest filtering only ever narrows ephemeral fan-out. Reliable traffic
	// — commits, locks, presence — must reach everyone regardless of viewport,
	// because losing it silently is the one thing this system may never do;
	// a block lock denial that only reached the visible half of the room would
	// leave the other half free to fight over a block they cannot see is held.
	var location domain.EventLocation
	if class == domain.ClassEphemeral {
		location = domain.LocationOf(envelope.Payload)
	}

	sent := 0
	for _, peer := range peers {
		if class == domain.ClassEphemeral {
			if !s.interest.Interested(peer.ID(), location) ||
				!s.interest.AllowsPreview(peer.ID(), envelope.Event) {
				continue
			}
			peer.SendEphemeral(envelope, coalesceKey(sender.ID(), envelope))
			sent++
			continue
		}
		if err := peer.SendReliable(envelope); err != nil {
			// The peer cannot keep up with traffic it is not allowed to lose.
			// Closing is the honest outcome: it will reconnect and resync.
			peer.Close("reliable queue overflow")
		}
	}

	if class == domain.ClassEphemeral && s.metrics != nil {
		// Recipients and events accumulate separately so a snapshot can derive
		// an average recipients-per-event rate rather than only ever seeing a
		// running total that says nothing about any single event.
		s.metrics.InterestRecipientsTotal.Add(int64(sent))
		s.metrics.InterestEventsTotal.Add(1)
		s.metrics.InterestFilteredTotal.Add(int64(len(peers) - sent))
	}
}

// RelayToPeer delivers a signalling message to exactly one connection.
//
// Every check here exists because the client chose the target: a sender could
// otherwise name any connection id it has seen and push SDP into a room it does
// not belong to. The lookup is scoped to the sender's own room, so a target
// outside it is simply not found.
func (s *RoomService) RelayToPeer(
	sender domain.Connection,
	envelope *domain.Envelope,
) (SignalingRejection, bool) {
	// Above the mesh ceiling, peer-to-peer stops being cheaper than the relay:
	// N peers means N² connections, and the server path is already open.
	if s.rooms.RoomSize(sender.NoteID()) > s.maxWebRTCPeers {
		return SignalingRoomTooLarge, false
	}

	target := domain.SignalingTarget(envelope.Payload)
	if target == "" {
		return SignalingNoTarget, false
	}
	if target == sender.ID() {
		return SignalingSelfTarget, false
	}

	peer, ok := s.rooms.ConnectionByID(sender.NoteID(), target)
	if !ok {
		return SignalingTargetAbsent, false
	}

	if err := peer.SendReliable(envelope); err != nil {
		peer.Close("reliable queue overflow")
		return SignalingTargetAbsent, false
	}
	return "", true
}

// Announce sends a server-generated event to a room.
//
// Exported so services whose state the room must learn about — block leases
// today — can publish without reaching into the store themselves. An empty
// exceptConnectionID includes everyone, which is what a lease expiry wants: the
// holder needs to hear it as much as the onlookers do.
func (s *RoomService) Announce(noteID, exceptConnectionID, event string, payload any) {
	if s.draining.Load() {
		return
	}
	s.broadcastReliable(noteID, exceptConnectionID, event, payload)
}

// Notify sends a server-generated event to exactly one connection — the answer
// to a request, which no other member has any business seeing.
func (s *RoomService) Notify(connection domain.Connection, event string, payload any) {
	if err := connection.SendReliable(s.envelope(connection.NoteID(), event, payload)); err != nil {
		connection.Close("reliable queue overflow")
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

// BeginDrain prevents further room writes and queues one reconnect instruction
// for every live transport. The event is direct rather than a room broadcast:
// it is server lifecycle control, not collaborative document state.
func (s *RoomService) BeginDrain(retryAfter time.Duration) int {
	s.draining.Store(true)

	connections := s.rooms.AllConnections()
	payload := map[string]any{"retryAfterMs": retryAfter.Milliseconds()}
	for _, connection := range connections {
		if err := connection.SendReliable(s.envelope(connection.NoteID(), "server.draining", payload)); err != nil {
			connection.Close("reliable queue overflow during drain")
		}
	}
	return len(connections)
}

// WaitForReliableDrain waits only for bounded reliable queues. It never waits
// for ephemeral previews, which are intentionally disposable during shutdown.
func (s *RoomService) WaitForReliableDrain(ctx context.Context, interval time.Duration) bool {
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		pending := 0
		for _, connection := range s.rooms.AllConnections() {
			pending += connection.PendingReliable()
		}
		if pending == 0 {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// CloseAll terminates the transport layer after the bounded reliable drain.
// Handler defers release locks, remove interest and leave rooms; because the
// service is draining those leaves are silent.
func (s *RoomService) CloseAll(reason string) int {
	connections := s.rooms.AllConnections()
	for _, connection := range connections {
		connection.Close(reason)
	}
	return len(connections)
}

func (s *RoomService) IsDraining() bool { return s.draining.Load() }

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
