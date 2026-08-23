package transport

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
	"mypol/go-realtime/internal/security"
)

// DefaultMaxDatagramBytes is a conservative ceiling for a preview frame.
// QUIC datagrams cannot be fragmented, so anything larger than the path MTU
// would simply be dropped; oversize frames fall back to the reliable stream.
const DefaultMaxDatagramBytes = 1100

// frameDeps is the slice of transport wiring that inbound frame handling needs,
// kept narrow so `handleClientFrame` cannot reach for anything else.
type frameDeps struct {
	now         application.Clock
	newID       func() string
	relay       func(domain.Connection, *domain.Envelope)
	authRefresh func(domain.Connection, json.RawMessage)
	// blockLock consumes the lock verbs, reporting true when it handled the
	// frame so the caller does not also relay it.
	blockLock blockLockHandler
	// transformGuard reports whether a geometry frame may proceed. Returning
	// false stops the relay.
	transformGuard func(domain.Connection, string, json.RawMessage) bool
	// interestUpdate records a viewport report. Consumed rather than relayed,
	// like auth.refresh: it is addressed to the server, and broadcasting it
	// would tell every peer exactly where everybody else is looking.
	interestUpdate func(domain.Connection, json.RawMessage)
	metrics        *observability.Metrics
	// Once draining starts, no already-open transport may create a new lock,
	// relay a preview or accept another application write.
	acceptApplicationWrites func() bool
	debug                   func(msg string, args ...any)
}

// authRefreshPayload carries a freshly issued canvas access token.
type authRefreshPayload struct {
	Token string `json:"token"`
}

// newAuthRefreshHandler extends a session in place from a refreshed token.
//
// The reply goes only to the connection that asked. Both outcomes are reported:
// a client that is told nothing cannot distinguish a rejected token from a
// dropped message, and would keep drawing on a session about to expire.
func newAuthRefreshHandler(
	sessions *application.SessionService,
	rooms *application.RoomService,
	newID func() string,
	now application.Clock,
	logger *slog.Logger,
) func(domain.Connection, json.RawMessage) {
	return func(connection domain.Connection, payload json.RawMessage) {
		var parsed authRefreshPayload
		if err := json.Unmarshal(payload, &parsed); err != nil || parsed.Token == "" {
			reply(connection, newID(), now, EventAuthRejected, map[string]any{
				"reason": "missing-token",
			})
			return
		}

		session, err := sessions.RefreshSession(connection.SessionID(), parsed.Token)
		if err != nil {
			// Never echo the validation detail: it tells a forger which part of
			// the token to fix next.
			logger.Debug("auth refresh rejected",
				"connectionId", connection.ID(), "error", err)
			reply(connection, newID(), now, EventAuthRejected, map[string]any{
				"reason": "rejected",
			})
			return
		}

		// A refresh may carry a demotion, which must reach the live connection
		// or the socket would keep the rights the old token granted.
		if session.Permission != connection.Permission() {
			rooms.ApplyPermission(session.ID, session.Permission)
		}

		reply(connection, newID(), now, EventAuthRefreshed, map[string]any{
			"sessionId":  session.ID,
			"permission": session.Permission.String(),
			"expiresAt":  session.ExpiresAt.UnixMilli(),
		})
	}
}

func reply(
	connection domain.Connection,
	messageID string,
	now application.Clock,
	event string,
	payload any,
) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = connection.SendReliable(&domain.Envelope{
		V:         domain.EnvelopeVersion,
		MessageID: messageID,
		SessionID: connection.SessionID(),
		Channel:   "note:" + connection.NoteID(),
		Event:     event,
		SentAt:    now().UnixMilli(),
		Payload:   encoded,
	})
}

// WebTransportDeps is what the /wt handler needs to admit and run a session.
type WebTransportDeps struct {
	Sessions       *application.SessionService
	Rooms          *application.RoomService
	Locks          *application.BlockLockService
	Interest       *application.InterestService
	Metrics        *observability.Metrics
	AllowedOrigins []string
	RateLimits     security.RateLimitSettings
	EphemeralQueue int
	ReliableQueue  int
	MaxDatagram    int
	IdleTimeout    time.Duration
	NewID          func() string
	Now            application.Clock
	Logger         *slog.Logger
	Health         *Health
}

// ServeWebTransport upgrades an authenticated HTTP/3 request to a WebTransport
// session and runs it until close.
//
// Admission is identical to the WebSocket path — same single-use ticket, same
// origin rules — because a second way in must not be a weaker way in.
func ServeWebTransport(server *webtransport.Server, deps WebTransportDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Health.IsDraining() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}

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

		// Redeemed before the upgrade, so an unauthenticated caller never gets
		// a session and a spent ticket is never retryable.
		ticket, err := deps.Sessions.ConsumeTicket(ticketValue)
		if err != nil {
			http.Error(w, "ticket rejected", http.StatusUnauthorized)
			return
		}
		if deps.Metrics != nil {
			deps.Metrics.TicketsConsumed.Add(1)
		}
		if deps.Health.IsDraining() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}

		session, err := server.Upgrade(w, r)
		if err != nil {
			return
		}

		runWebTransportSession(r.Context(), deps, ticket, session)
	}
}

func runWebTransportSession(
	parent context.Context,
	deps WebTransportDeps,
	ticket *domain.ConnectionTicket,
	session *webtransport.Session,
) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// The client opens one bidirectional stream to carry reliable traffic in
	// both directions. Waiting for it here means a session that never sends one
	// is discarded rather than lingering.
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 10*time.Second)
	stream, err := session.AcceptStream(acceptCtx)
	acceptCancel()
	if err != nil {
		_ = session.CloseWithError(0, "no control stream")
		return
	}

	now := deps.Now()
	maxDatagram := deps.MaxDatagram
	if maxDatagram <= 0 {
		maxDatagram = DefaultMaxDatagramBytes
	}

	connection := newWTConnection(
		deps.NewID(), ticket, session, stream,
		deps.EphemeralQueue, deps.ReliableQueue, maxDatagram, deps.Metrics, now)
	limits := security.NewRateLimits(deps.RateLimits, now)

	deps.Rooms.Join(connection)
	if deps.Metrics != nil {
		deps.Metrics.ActiveConnections.Add(1)
		deps.Metrics.ActiveRooms.Store(int64(deps.Rooms.RoomCount()))
	}
	defer releaseLocksOnDisconnect(deps.Locks, deps.Rooms, deps.Metrics, connection.ID())
	defer deps.Interest.Remove(connection.ID())
	defer func() {
		deps.Rooms.Leave(connection)
		if deps.Metrics != nil {
			deps.Metrics.ActiveConnections.Add(-1)
			deps.Metrics.ActiveRooms.Store(int64(deps.Rooms.RoomCount()))
		}
	}()
	defer connection.Close("handler returned")

	go connection.writePump(ctx)

	deps.Logger.Info("webtransport session opened",
		"connectionId", connection.ID(),
		"sessionId", connection.SessionID(),
		"noteId", connection.NoteID(),
		"permission", connection.Permission().String())

	frames := deps.frameDeps()

	// Datagrams and the control stream are independent sources, so each gets its
	// own reader; whichever ends first tears the session down.
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		readDatagrams(ctx, deps, frames, connection, limits, session)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		_ = readStreamFrames(stream, func(payload []byte) {
			handleClientFrame(frames, connection, limits, payload)
		})
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}

	deps.Logger.Info("webtransport session closed",
		"connectionId", connection.ID(),
		"droppedFrames", connection.Dropped())
}

func readDatagrams(
	ctx context.Context,
	deps WebTransportDeps,
	frames frameDeps,
	connection *wtConnection,
	limits *security.RateLimits,
	session *webtransport.Session,
) {
	for {
		// An idle session is reaped: a client that stops sending — including one
		// whose network vanished without a close — must not hold a slot.
		readCtx, cancel := context.WithTimeout(ctx, deps.IdleTimeout)
		payload, err := session.ReceiveDatagram(readCtx)
		cancel()

		if err != nil {
			connection.Close("datagram read ended")
			return
		}
		handleClientFrame(frames, connection, limits, payload)
	}
}

func (d WebTransportDeps) frameDeps() frameDeps {
	return frameDeps{
		now:   d.Now,
		newID: d.NewID,
		relay: func(connection domain.Connection, envelope *domain.Envelope) {
			d.Rooms.Relay(connection, envelope)
		},
		authRefresh:             newAuthRefreshHandler(d.Sessions, d.Rooms, d.NewID, d.Now, d.Logger),
		blockLock:               newBlockLockHandler(d.Locks, d.Rooms, d.Metrics),
		transformGuard:          newTransformGuard(d.Locks, d.Rooms, d.Metrics),
		interestUpdate:          newInterestUpdateHandler(d.Interest, d.Metrics),
		metrics:                 d.Metrics,
		acceptApplicationWrites: func() bool { return !d.Health.IsDraining() },
		debug:                   func(msg string, args ...any) { d.Logger.Debug(msg, args...) },
	}
}

func (d WebSocketDeps) frameDeps() frameDeps {
	return frameDeps{
		now:   d.Now,
		newID: d.NewID,
		relay: func(connection domain.Connection, envelope *domain.Envelope) {
			d.Rooms.Relay(connection, envelope)
		},
		authRefresh:             newAuthRefreshHandler(d.Sessions, d.Rooms, d.NewID, d.Now, d.Logger),
		blockLock:               newBlockLockHandler(d.Locks, d.Rooms, d.Metrics),
		transformGuard:          newTransformGuard(d.Locks, d.Rooms, d.Metrics),
		interestUpdate:          newInterestUpdateHandler(d.Interest, d.Metrics),
		metrics:                 d.Metrics,
		acceptApplicationWrites: func() bool { return !d.Health.IsDraining() },
		debug:                   func(msg string, args ...any) { d.Logger.Debug(msg, args...) },
	}
}
