package transport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/config"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/security"
	"mypol/go-realtime/internal/testsupport"
)

// wsHarness runs the real router over a real HTTP server, so these tests
// exercise an actual socket rather than a stand-in.
type wsHarness struct {
	server   *httptest.Server
	keys     *testsupport.KeyPair
	sessions *application.SessionService
	rooms    *application.RoomService
	locks    *application.BlockLockService
	interest *application.InterestService
	health   *Health
}

func newWSHarness(t *testing.T) *wsHarness {
	t.Helper()

	keys, err := testsupport.NewKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	validator, err := security.NewCanvasJWTValidator(
		keys.PublicPEM, testsupport.Issuer, testsupport.Audience, 0)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	clock := time.Now
	sessions := application.NewSessionService(
		infrastructure.NewMemorySessionStore(),
		infrastructure.NewMemoryTicketStore(),
		validator, 30*time.Second, clock)

	counter := 0
	newID := func() string {
		counter++
		return "id-" + strings.Repeat("x", counter%3) + time.Now().Format("150405.000000000")
	}

	rooms := application.NewRoomService(infrastructure.NewMemoryRoomStore(), newID, clock)
	locks := application.NewBlockLockService(
		infrastructure.NewMemoryLockStore(),
		application.BlockLockSettings{Lease: 5 * time.Second, MaxPerSession: 4},
		clock)
	health := &Health{}

	interest := application.NewInterestService(infrastructure.NewMemoryInterestIndex())

	cfg := &config.Config{
		AllowedOrigins:   []string{"http://localhost:3000"},
		WebSocketURL:     "ws://example/ws",
		WebRTCMaxPeers:   6,
		SessionHeartbeat: 15 * time.Second,
		BlockLockLease:   5 * time.Second,
		BlockLockRenew:   2 * time.Second,

		MaxActiveBlockLocksPerSess: 4,
	}

	handlers := NewHandlers(sessions, rooms,
		security.NewHMACValidator(security.HMACKey{KeyID: "k", Secret: "s"}, security.HMACKey{}, 30*time.Second),
		cfg, health, clock)
	rooms.SetInterest(interest, handlers.Metrics())

	wsHandler := ServeWebSocket(WebSocketDeps{
		Sessions:       sessions,
		Locks:          locks,
		Interest:       interest,
		Metrics:        handlers.Metrics(),
		Rooms:          rooms,
		AllowedOrigins: cfg.AllowedOrigins,
		RateLimits: security.RateLimitSettings{
			EphemeralPerSecond: 160, EphemeralBurst: 240,
			ReliablePerSecond: 60, ReliableBurst: 120,
			SignalingPerSecond: 30, SignalingBurst: 60,
		},
		EphemeralQueue: 64,
		ReliableQueue:  128,
		IdleTimeout:    5 * time.Second,
		NewID:          newID,
		Now:            clock,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Health:         health,
	})

	harness := &wsHarness{
		server:   httptest.NewServer(NewRouter(handlers, cfg.AllowedOrigins, wsHandler)),
		keys:     keys,
		sessions: sessions,
		rooms:    rooms,
		locks:    locks,
		interest: interest,
		health:   health,
	}
	t.Cleanup(harness.server.Close)
	return harness
}

// ticketFor bootstraps a session and returns its single-use connection ticket.
func (h *wsHarness) ticketFor(t *testing.T, in testsupport.ClaimsInput) string {
	t.Helper()
	token, err := h.keys.Sign(testsupport.Claims(in))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	result, err := h.sessions.Bootstrap(token)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	return result.Ticket.Value
}

func (h *wsHarness) wsURL(ticket string) string {
	return "ws" + strings.TrimPrefix(h.server.URL, "http") + "/ws?ticket=" + ticket
}

func (h *wsHarness) connect(t *testing.T, in testsupport.ClaimsInput) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	socket, _, err := websocket.Dial(ctx, h.wsURL(h.ticketFor(t, in)), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close(websocket.StatusNormalClosure, "test over") })
	return socket
}

func readEnvelope(t *testing.T, socket *websocket.Conn) *domain.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, data, err := socket.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope domain.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &envelope
}

func send(t *testing.T, socket *websocket.Conn, event, payload string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	frame, _ := json.Marshal(domain.Envelope{
		V: domain.EnvelopeVersion, Event: event, Payload: json.RawMessage(payload),
	})
	if err := socket.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// ── admission ───────────────────────────────────────────────────────────────

func TestConnectRequiresATicket(t *testing.T) {
	h := newWSHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.server.URL, "http")+"/ws", nil); err == nil {
		t.Fatal("a socket without a ticket must be refused")
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	h := newWSHarness(t)
	ticket := h.ticketFor(t, testsupport.ClaimsInput{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, _, err := websocket.Dial(ctx, h.wsURL(ticket), nil)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer first.Close(websocket.StatusNormalClosure, "")

	// Replaying a spent ticket must not open a second socket.
	if _, _, err := websocket.Dial(ctx, h.wsURL(ticket), nil); err == nil {
		t.Fatal("a spent ticket must not be reusable")
	}
}

func TestConnectRefusedWhileDraining(t *testing.T) {
	h := newWSHarness(t)
	ticket := h.ticketFor(t, testsupport.ClaimsInput{})
	h.health.StartDraining()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, _, err := websocket.Dial(ctx, h.wsURL(ticket), nil); err == nil {
		t.Fatal("a draining server must not accept new sockets")
	}
}

// CORS does not apply to WebSockets, so Origin must be checked explicitly.
func TestDisallowedOriginIsRejected(t *testing.T) {
	h := newWSHarness(t)
	ticket := h.ticketFor(t, testsupport.ClaimsInput{})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, err := websocket.Dial(ctx, h.wsURL(ticket), &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}},
	})
	if err == nil {
		t.Fatal("a socket from a disallowed origin must be refused")
	}
}

// ── presence ────────────────────────────────────────────────────────────────

func TestFirstMessageIsTheRoomRoster(t *testing.T) {
	h := newWSHarness(t)
	socket := h.connect(t, testsupport.ClaimsInput{})

	envelope := readEnvelope(t, socket)

	if envelope.Event != application.EventRoomMembers {
		t.Fatalf("first event = %q, want room.members", envelope.Event)
	}
	if envelope.V != domain.EnvelopeVersion {
		t.Errorf("envelope version = %d", envelope.V)
	}
}

func TestPeerLearnsAboutAJoin(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1"})
	readEnvelope(t, first) // its own roster

	h.connect(t, testsupport.ClaimsInput{SessionID: "s2"})

	envelope := readEnvelope(t, first)
	if envelope.Event != application.EventPresenceJoined {
		t.Fatalf("event = %q, want presence.joined", envelope.Event)
	}
}

// ── relay ───────────────────────────────────────────────────────────────────

func TestCursorReachesPeerWithServerStampedIdentity(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", UserID: "user-1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", UserID: "user-2"})
	readEnvelope(t, second) // roster
	readEnvelope(t, first)  // presence.joined

	send(t, second, "cursor.moved", `{"pageId":"p1","x":10,"y":20}`)

	envelope := readEnvelope(t, first)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q", envelope.Event)
	}
	// Identity comes from the authenticated connection, not the client's claim.
	if envelope.ActorID == nil || *envelope.ActorID != "user-2" {
		t.Errorf("actorId = %v, want user-2", envelope.ActorID)
	}
	if envelope.SessionID != "s2" {
		t.Errorf("sessionId = %q, want s2", envelope.SessionID)
	}
	if envelope.Origin == nil || *envelope.Origin == "" {
		t.Error("origin should be the sender's connection id")
	}
}

// The whole point of Phase 14: a collaborator learns a media block exists
// before the file behind it has even started uploading, over the realtime
// path rather than waiting for autosave and the durable event that follows it.
func TestANewMediaBlockReachesAPeerImmediately(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", UserID: "user-1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", UserID: "user-2"})
	readEnvelope(t, second) // roster
	readEnvelope(t, first)  // presence.joined

	send(t, second, "block.created", `{
		"blockId": "block-1", "pageId": "page-1", "blockType": "image",
		"x": 10, "y": 20, "width": 360, "height": 240, "rotation": 0,
		"content": "{\"type\":\"image\",\"attachmentId\":null,\"status\":\"uploading\"}"
	}`)

	envelope := readEnvelope(t, first)
	if envelope.Event != "block.created" {
		t.Fatalf("event = %q, want block.created", envelope.Event)
	}
}

// Loading progress must reach peers too — not only the block's first
// appearance — so a collaborator's placeholder can move from "uploading" to
// "ready" without waiting on autosave.
func TestMediaStatusReachesAPeer(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", UserID: "user-1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", UserID: "user-2"})
	readEnvelope(t, second)
	readEnvelope(t, first)

	send(t, second, "block.status", `{"blockId":"block-1","status":"ready","attachmentId":"att-1"}`)

	envelope := readEnvelope(t, first)
	if envelope.Event != "block.status" {
		t.Fatalf("event = %q, want block.status", envelope.Event)
	}
}

// A viewer may watch a media upload happen but must not be able to conjure a
// block into a canvas it has no write access to — the same rule that already
// stops a viewer drawing ink or moving a block.
func TestAViewerCannotAnnounceAMediaBlock(t *testing.T) {
	h := newWSHarness(t)

	editor := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", Permission: "edit"})
	readEnvelope(t, editor)

	viewer := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", Permission: "view"})
	readEnvelope(t, viewer)
	readEnvelope(t, editor)

	// Dropped by the server...
	send(t, viewer, "block.created", `{
		"blockId": "block-1", "pageId": "page-1", "blockType": "image",
		"x": 0, "y": 0, "width": 100, "height": 100, "rotation": 0,
		"content": "{}"
	}`)
	// ...but a cursor still gets through, so the next frame the editor sees is
	// the cursor rather than the forged block.
	send(t, viewer, "cursor.moved", `{"pageId":"p","x":1,"y":2}`)

	envelope := readEnvelope(t, editor)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q — a viewer's block.created must not be relayed", envelope.Event)
	}
}

// A client must not be able to publish into a room it is not in.
func TestChannelIsForcedToTheConnectionsNote(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", NoteID: "note-1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", NoteID: "note-1"})
	readEnvelope(t, second)
	readEnvelope(t, first)

	// Claim a different channel; the server must overwrite it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	frame, _ := json.Marshal(map[string]any{
		"v": 2, "event": "cursor.moved", "channel": "note:someone-elses-note",
		"payload": map[string]int{"x": 1},
	})
	if err := second.Write(ctx, websocket.MessageText, frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	envelope := readEnvelope(t, first)
	if envelope.Channel != "note:note-1" {
		t.Fatalf("channel = %q, want note:note-1", envelope.Channel)
	}
}

func TestViewerCannotDrawButCanMoveACursor(t *testing.T) {
	h := newWSHarness(t)

	editor := h.connect(t, testsupport.ClaimsInput{SessionID: "s1", Permission: "edit"})
	readEnvelope(t, editor)

	viewer := h.connect(t, testsupport.ClaimsInput{SessionID: "s2", Permission: "view"})
	readEnvelope(t, viewer)
	readEnvelope(t, editor)

	// Ink from a viewer is dropped by the server...
	send(t, viewer, "ink.started", `{"strokeId":"s"}`)
	// ...but a cursor still gets through, so the next frame the editor sees is
	// the cursor rather than the ink.
	send(t, viewer, "cursor.moved", `{"pageId":"p","x":1,"y":2}`)

	envelope := readEnvelope(t, editor)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q — a viewer's ink must not be relayed", envelope.Event)
	}
}

func TestClientCannotForgeADurableEvent(t *testing.T) {
	h := newWSHarness(t)

	first := h.connect(t, testsupport.ClaimsInput{SessionID: "s1"})
	readEnvelope(t, first)

	second := h.connect(t, testsupport.ClaimsInput{SessionID: "s2"})
	readEnvelope(t, second)
	readEnvelope(t, first)

	// Only the server may claim something was persisted.
	send(t, second, "note.blocks.changed", `{"noteId":"x"}`)
	send(t, second, "cursor.moved", `{"pageId":"p","x":1,"y":2}`)

	envelope := readEnvelope(t, first)
	if envelope.Event != "cursor.moved" {
		t.Fatalf("event = %q — a durable event must not be relayable", envelope.Event)
	}
}

// ── revocation ──────────────────────────────────────────────────────────────

func TestRevokingASessionClosesItsSocket(t *testing.T) {
	h := newWSHarness(t)
	socket := h.connect(t, testsupport.ClaimsInput{SessionID: "doomed"})
	readEnvelope(t, socket)

	if closed := h.rooms.DisconnectSession("doomed", "revoked"); closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := socket.Read(ctx); err == nil {
		t.Fatal("the socket should be closed after revocation")
	}
}
