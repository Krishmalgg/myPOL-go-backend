package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/coder/websocket"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/security"
)

const (
	// MaxFrameBytes bounds a single client message. Canvas frames are small;
	// an unbounded reader is a trivial memory exhaustion vector.
	MaxFrameBytes = 256 * 1024

	writeTimeout = 10 * time.Second
)

// WebSocketDeps is what the connect handler needs to admit and run a socket.
type WebSocketDeps struct {
	Sessions       *application.SessionService
	Rooms          *application.RoomService
	AllowedOrigins []string
	RateLimits     security.RateLimitSettings
	EphemeralQueue int
	ReliableQueue  int
	IdleTimeout    time.Duration
	NewID          func() string
	Now            application.Clock
	Logger         *slog.Logger
	Health         *Health
}

// ServeWebSocket upgrades an authenticated connection and runs it until close.
//
// Authentication happens before the upgrade: the ticket is redeemed first, so
// an unauthenticated caller never gets as far as an open socket.
func ServeWebSocket(deps WebSocketDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Health.IsDraining() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}

		// CORS does not apply to WebSockets, so the Origin header must be
		// checked explicitly or any site could open a socket with the user's
		// ticket. A missing Origin is a non-browser client, which is fine.
		if origin := r.Header.Get("Origin"); origin != "" &&
			!slices.Contains(deps.AllowedOrigins, origin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}

		ticketValue := r.URL.Query().Get("ticket")
		if ticketValue == "" {
			http.Error(w, "ticket required", http.StatusUnauthorized)
			return
		}

		// Redeeming before the upgrade also makes the ticket single-use even if
		// the handshake then fails — a spent ticket must never be retryable.
		ticket, err := deps.Sessions.ConsumeTicket(ticketValue)
		if err != nil {
			http.Error(w, "ticket rejected", http.StatusUnauthorized)
			return
		}

		socket, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Origin was already checked above against the configured list.
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		socket.SetReadLimit(MaxFrameBytes)

		runConnection(r.Context(), deps, ticket, socket)
	}
}

func runConnection(
	parent context.Context,
	deps WebSocketDeps,
	ticket *domain.ConnectionTicket,
	socket *websocket.Conn,
) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	now := deps.Now()
	connection := newWSConnection(
		deps.NewID(), ticket, socket, deps.EphemeralQueue, deps.ReliableQueue, now)
	limits := security.NewRateLimits(deps.RateLimits, now)

	deps.Rooms.Join(connection)
	defer deps.Rooms.Leave(connection)
	defer connection.Close("handler returned")

	go connection.writePump(ctx, writeTimeout)

	deps.Logger.Info("connection opened",
		"connectionId", connection.ID(),
		"sessionId", connection.SessionID(),
		"noteId", connection.NoteID(),
		"permission", connection.Permission().String())

	readPump(ctx, deps, connection, socket, limits)

	deps.Logger.Info("connection closed",
		"connectionId", connection.ID(),
		"droppedFrames", connection.Dropped())
}

// readPump consumes client frames until the socket closes.
func readPump(
	ctx context.Context,
	deps WebSocketDeps,
	connection *wsConnection,
	socket *websocket.Conn,
	limits *security.RateLimits,
) {
	for {
		// An idle socket is reaped: a client that stops sending — including one
		// whose network vanished without a close frame — must not hold a slot.
		readCtx, cancel := context.WithTimeout(ctx, deps.IdleTimeout)
		_, data, err := socket.Read(readCtx)
		cancel()

		if err != nil {
			if !errors.Is(err, context.Canceled) {
				connection.Close("read ended")
			}
			return
		}

		handleFrame(deps, connection, limits, data)
	}
}

// handleFrame validates one client message and relays it.
//
// Order matters: parse, then rate limit, then authorise, then stamp. Rate
// limiting before permission checks means a client cannot use rejected messages
// as a free channel to probe what it is allowed to send.
func handleFrame(
	deps WebSocketDeps,
	connection *wsConnection,
	limits *security.RateLimits,
	data []byte,
) {
	var envelope domain.Envelope
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Event == "" {
		return
	}

	class := domain.ClassifyEvent(envelope.Event)
	now := deps.Now()

	if !limits.Allow(class, now) {
		deps.Logger.Debug("rate limited",
			"connectionId", connection.ID(), "event", envelope.Event)
		return
	}

	if !connection.Permission().MayPublish(envelope.Event) {
		deps.Logger.Debug("permission denied",
			"connectionId", connection.ID(),
			"event", envelope.Event,
			"permission", connection.Permission().String())
		return
	}

	// Identity and channel come from the authenticated connection, never from
	// the client's own claims — otherwise a client could publish into another
	// note's room or forge another user's cursor.
	envelope.Stamp(connection.SessionID(), connection.ID(), connection.UserID(), now.UnixMilli())
	envelope.Channel = "note:" + connection.NoteID()
	if envelope.MessageID == "" {
		envelope.MessageID = deps.NewID()
	}

	deps.Rooms.Relay(connection, &envelope)
}
