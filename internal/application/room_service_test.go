package application

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
)

// fakeConnection records what was sent instead of writing to a socket, and can
// be told to refuse reliable sends to simulate a peer that cannot keep up.
type fakeConnection struct {
	id, sessionID, userID, noteID string

	mu           sync.Mutex
	permission   domain.Permission
	reliable     []*domain.Envelope
	ephemeral    []*domain.Envelope
	coalesceKeys []string
	closed       bool
	closeReason  string
	refuse       bool
}

func newFakeConnection(id, sessionID, userID, noteID string) *fakeConnection {
	return &fakeConnection{
		id: id, sessionID: sessionID, userID: userID, noteID: noteID,
		permission: domain.PermissionEdit,
	}
}

func (c *fakeConnection) ID() string             { return c.id }
func (c *fakeConnection) SessionID() string      { return c.sessionID }
func (c *fakeConnection) UserID() string         { return c.userID }
func (c *fakeConnection) NoteID() string         { return c.noteID }
func (c *fakeConnection) ConnectedAt() time.Time { return time.Unix(0, 0) }

func (c *fakeConnection) Permission() domain.Permission {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.permission
}

func (c *fakeConnection) SetPermission(p domain.Permission) {
	c.mu.Lock()
	c.permission = p
	c.mu.Unlock()
}

func (c *fakeConnection) SendReliable(e *domain.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuse {
		return errFull
	}
	c.reliable = append(c.reliable, e)
	return nil
}

func (c *fakeConnection) SendEphemeral(e *domain.Envelope, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ephemeral = append(c.ephemeral, e)
	c.coalesceKeys = append(c.coalesceKeys, key)
}

func (c *fakeConnection) Close(reason string) {
	c.mu.Lock()
	c.closed = true
	c.closeReason = reason
	c.mu.Unlock()
}

func (c *fakeConnection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeConnection) events(reliable bool) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	source := c.ephemeral
	if reliable {
		source = c.reliable
	}
	names := make([]string, 0, len(source))
	for _, envelope := range source {
		names = append(names, envelope.Event)
	}
	return names
}

type staticError string

func (e staticError) Error() string { return string(e) }

const errFull = staticError("queue full")

func newRooms() (*RoomService, *infrastructure.MemoryRoomStore) {
	store := infrastructure.NewMemoryRoomStore()
	counter := 0
	service := NewRoomService(store, func() string {
		counter++
		return "msg-" + string(rune('a'+counter%26))
	}, func() time.Time { return time.Unix(1000, 0) })
	return service, store
}

func envelopeFor(event, payload string) *domain.Envelope {
	return &domain.Envelope{
		V:       domain.EnvelopeVersion,
		Event:   event,
		Payload: json.RawMessage(payload),
	}
}

// ── join / presence ─────────────────────────────────────────────────────────

func TestJoinSendsRosterToNewcomerAndAnnouncesToRoom(t *testing.T) {
	rooms, _ := newRooms()
	first := newFakeConnection("c1", "s1", "u1", "note-1")
	second := newFakeConnection("c2", "s2", "u2", "note-1")

	rooms.Join(first)
	rooms.Join(second)

	// The newcomer learns who is already here.
	if got := second.events(true); len(got) == 0 || got[0] != EventRoomMembers {
		t.Fatalf("second connection events = %v, want room.members first", got)
	}
	// And the room hears about the newcomer.
	if got := first.events(true); len(got) == 0 || got[len(got)-1] != EventPresenceJoined {
		t.Fatalf("first connection events = %v, want presence.joined", got)
	}
}

// The roster handed to a newcomer must already include them, or a peer could
// receive presence.joined for someone absent from the roster they were given.
func TestRosterIncludesTheJoiningConnection(t *testing.T) {
	rooms, _ := newRooms()
	first := newFakeConnection("c1", "s1", "u1", "note-1")
	second := newFakeConnection("c2", "s2", "u2", "note-1")

	rooms.Join(first)
	rooms.Join(second)

	second.mu.Lock()
	roster := second.reliable[0]
	second.mu.Unlock()

	var payload struct {
		Members []domain.Member `json:"members"`
	}
	if err := json.Unmarshal(roster.Payload, &payload); err != nil {
		t.Fatalf("decode roster: %v", err)
	}
	if len(payload.Members) != 2 {
		t.Fatalf("roster has %d members, want 2", len(payload.Members))
	}
}

func TestLeaveAnnouncesDeparture(t *testing.T) {
	rooms, store := newRooms()
	first := newFakeConnection("c1", "s1", "u1", "note-1")
	second := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(first)
	rooms.Join(second)

	rooms.Leave(second)

	if got := first.events(true); got[len(got)-1] != EventPresenceLeft {
		t.Fatalf("events = %v, want presence.left last", got)
	}
	if store.ConnectionCount() != 1 {
		t.Errorf("connection count = %d, want 1", store.ConnectionCount())
	}
}

// One user with two tabs is two connections, and both must appear.
func TestPresenceIsPerConnectionNotPerUser(t *testing.T) {
	rooms, store := newRooms()
	rooms.Join(newFakeConnection("tab1", "s1", "same-user", "note-1"))
	rooms.Join(newFakeConnection("tab2", "s2", "same-user", "note-1"))

	if store.ConnectionCount() != 2 {
		t.Fatalf("connection count = %d, want 2", store.ConnectionCount())
	}
}

func TestRoomsAreIsolatedByNote(t *testing.T) {
	rooms, _ := newRooms()
	here := newFakeConnection("c1", "s1", "u1", "note-1")
	elsewhere := newFakeConnection("c2", "s2", "u2", "note-2")

	rooms.Join(here)
	rooms.Join(elsewhere)

	if len(elsewhere.events(true)) != 1 {
		t.Error("a connection on another note must not hear this room's presence")
	}
}

// ── relay ───────────────────────────────────────────────────────────────────

func TestRelayReachesPeersButNotTheSender(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"x":1}`))

	if len(peer.events(false)) != 1 {
		t.Errorf("peer ephemeral = %v, want one frame", peer.events(false))
	}
	if len(sender.events(false)) != 0 {
		t.Error("sender must not receive its own echo")
	}
}

func TestEphemeralAndReliableTakeDifferentPaths(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	before := len(peer.events(true))
	rooms.Relay(sender, envelopeFor("ink.points", `{"strokeId":"s"}`))
	rooms.Relay(sender, envelopeFor("ink.commit", `{"strokeId":"s"}`))

	if len(peer.events(false)) != 1 {
		t.Errorf("ephemeral = %v, want the preview", peer.events(false))
	}
	if len(peer.events(true))-before != 1 {
		t.Errorf("reliable = %v, want the commit", peer.events(true))
	}
}

// Two strokes from one author are independent streams; sharing a key would let
// the second evict the first mid-draw.
func TestCoalesceKeySeparatesStreams(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	rooms.Relay(sender, envelopeFor("ink.points", `{"strokeId":"stroke-a"}`))
	rooms.Relay(sender, envelopeFor("ink.points", `{"strokeId":"stroke-b"}`))

	peer.mu.Lock()
	keys := append([]string(nil), peer.coalesceKeys...)
	peer.mu.Unlock()

	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("expected distinct coalesce keys, got %v", keys)
	}
}

// Reliable state must never be silently dropped; closing is the honest outcome.
func TestPeerThatCannotAcceptReliableTrafficIsClosed(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	peer.mu.Lock()
	peer.refuse = true
	peer.mu.Unlock()

	rooms.Relay(sender, envelopeFor("ink.commit", `{"strokeId":"s"}`))

	if !peer.isClosed() {
		t.Fatal("a peer that cannot take reliable traffic must be closed, not silently skipped")
	}
}

// ── revocation ──────────────────────────────────────────────────────────────

func TestDisconnectSessionClosesEveryConnectionForThatSession(t *testing.T) {
	rooms, _ := newRooms()
	one := newFakeConnection("c1", "session-x", "u1", "note-1")
	two := newFakeConnection("c2", "session-x", "u1", "note-1")
	other := newFakeConnection("c3", "session-y", "u2", "note-1")
	rooms.Join(one)
	rooms.Join(two)
	rooms.Join(other)

	if closed := rooms.DisconnectSession("session-x", "revoked"); closed != 2 {
		t.Errorf("closed = %d, want 2", closed)
	}
	if !one.isClosed() || !two.isClosed() {
		t.Error("both connections for the session should be closed")
	}
	if other.isClosed() {
		t.Error("another session must not be affected")
	}
}

func TestDisconnectUserFromNoteClosesEveryTab(t *testing.T) {
	rooms, _ := newRooms()
	tab1 := newFakeConnection("c1", "s1", "user-1", "note-1")
	tab2 := newFakeConnection("c2", "s2", "user-1", "note-1")
	elsewhere := newFakeConnection("c3", "s3", "user-1", "note-2")
	rooms.Join(tab1)
	rooms.Join(tab2)
	rooms.Join(elsewhere)

	if closed := rooms.DisconnectUserFromNote("note-1", "user-1", "revoked"); closed != 2 {
		t.Errorf("closed = %d, want 2", closed)
	}
	if elsewhere.isClosed() {
		t.Error("the user's connection on another note must survive")
	}
}

// Demotion must not drop the socket the user is drawing on.
func TestApplyPermissionChangesLiveConnectionsInPlace(t *testing.T) {
	rooms, _ := newRooms()
	connection := newFakeConnection("c1", "session-x", "u1", "note-1")
	rooms.Join(connection)

	if applied := rooms.ApplyPermission("session-x", domain.PermissionView); applied != 1 {
		t.Errorf("applied = %d, want 1", applied)
	}
	if connection.Permission() != domain.PermissionView {
		t.Errorf("permission = %q, want view", connection.Permission())
	}
	if connection.isClosed() {
		t.Error("a permission change must not close the connection")
	}
}
