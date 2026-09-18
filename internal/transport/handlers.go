package transport

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/config"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
	"mypol/go-realtime/internal/security"
)

// MaxControlBodyBytes bounds internal control payloads. They are tiny by
// design, and an unbounded reader on an authenticated-but-cheap endpoint is a
// denial-of-service waiting to happen.
const MaxControlBodyBytes = 64 * 1024

// Health reports liveness and readiness separately.
//
// Liveness means the process is up; readiness means it should receive traffic.
// They diverge during a drain: a shutting-down instance is still alive but must
// stop being routed to, which is what lets deploys finish in-flight work.
type Health struct {
	draining atomic.Bool
}

func (h *Health) StartDraining() { h.draining.Store(true) }
func (h *Health) IsDraining() bool {
	return h.draining.Load()
}

// BootstrapResponse is the contract with the browser. Field names match the
// frontend's expectations exactly.
type BootstrapResponse struct {
	SessionID        string      `json:"sessionId"`
	ConnectionTicket string      `json:"connectionTicket"`
	TicketExpiresAt  time.Time   `json:"ticketExpiresAt"`
	WebSocketURL     string      `json:"websocketUrl"`
	WebTransportURL  string      `json:"webTransportUrl,omitempty"`
	ICEServers       []ICEServer `json:"iceServers"`
	MaxWebRTCPeers   int         `json:"maxWebRtcPeers"`
	Permission       string      `json:"permission"`
	NoteID           string      `json:"noteId"`
	HeartbeatSeconds int         `json:"heartbeatSeconds"`
	// Omitted when disabled. Its presence is the frontend's compatibility
	// handshake: a newer browser remains on JSON against an older Go server.
	BinaryEphemeralVersion int `json:"binaryEphemeralVersion,omitempty"`
	// Lease cadence, served rather than hardcoded in the client: the server is
	// the party that enforces expiry, so it is the party that gets to say how
	// often a holder must refresh.
	BlockLockLeaseSeconds int `json:"blockLockLeaseSeconds"`
	BlockLockRenewSeconds int `json:"blockLockRenewSeconds"`
}

// ICEServer is the STUN/TURN shape browsers expect. Empty for now: real TURN
// credentials are short-lived and minted per session, which is later work — the
// field exists so the client contract does not change when they arrive.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Handlers wires HTTP to the application layer.
type Handlers struct {
	sessions  *application.SessionService
	rooms     *application.RoomService
	hmac      *security.HMACValidator
	bootstrap *security.BootstrapLimiter
	metrics   *observability.Metrics
	cfg       *config.Config
	health    *Health
	now       application.Clock
}

func NewHandlers(
	sessions *application.SessionService,
	rooms *application.RoomService,
	hmac *security.HMACValidator,
	cfg *config.Config,
	health *Health,
	now application.Clock,
) *Handlers {
	if now == nil {
		now = time.Now
	}
	return &Handlers{
		sessions: sessions,
		rooms:    rooms,
		hmac:     hmac,
		bootstrap: security.NewBootstrapLimiter(security.BootstrapLimitSettings{
			PerUserPerMinute: cfg.BootstrapRatePerUserPerMinute,
			PerUserBurst:     cfg.BootstrapBurstPerUser,
			PerIPPerMinute:   cfg.BootstrapRatePerIPPerMinute,
			PerIPBurst:       cfg.BootstrapBurstPerIP,
		}, now()),
		metrics: observability.New(),
		cfg:     cfg,
		health:  health,
		now:     now,
	}
}

// Metrics exposes the counter set so the router can serve it and the server can
// record connection lifecycle events against it.
func (h *Handlers) Metrics() *observability.Metrics { return h.metrics }

// ── health ──────────────────────────────────────────────────────────────────

func (h *Handlers) Healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) Readyz(w http.ResponseWriter, _ *http.Request) {
	if h.health.IsDraining() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ── bootstrap ───────────────────────────────────────────────────────────────

// Bootstrap exchanges a canvas access token for a session and a single-use
// connection ticket.
func (h *Handlers) Bootstrap(w http.ResponseWriter, r *http.Request) {
	if h.health.IsDraining() {
		// Refuse new sessions while draining so a shutting-down instance does
		// not accept work it cannot finish.
		writeError(w, http.StatusServiceUnavailable, "DRAINING", "Server is shutting down.")
		return
	}

	now := h.now()

	// Checked before the token is parsed, so an unauthenticated flood cannot
	// make the server do signature verification work.
	if !h.bootstrap.AllowIP(security.ClientIP(r), now) {
		h.metrics.BootstrapThrottled.Add(1)
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests.")
		return
	}

	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "MISSING_TOKEN", "A canvas access token is required.")
		return
	}

	result, err := h.sessions.Bootstrap(token)
	if err != nil {
		h.metrics.SessionAuthFailures.Add(1)
		// Never echo the validation detail: it would tell an attacker which part
		// of a forged token to fix next.
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "The canvas access token was rejected.")
		return
	}

	// Only now is the identity trustworthy, so the per-user budget — the limit
	// that actually matters — is applied against a signed claim rather than a
	// header anyone could set.
	if !h.bootstrap.AllowUser(result.Session.UserID, now) {
		h.metrics.BootstrapThrottled.Add(1)
		_, _ = h.sessions.RevokeSession(result.Session.ID)
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many session requests.")
		return
	}

	h.metrics.TicketsIssued.Add(1)

	response := BootstrapResponse{
		SessionID:             result.Session.ID,
		ConnectionTicket:      result.Ticket.Value,
		TicketExpiresAt:       result.TicketExpiresAt,
		WebSocketURL:          h.websocketURL(r),
		WebTransportURL:       h.cfg.WebTransportURL,
		ICEServers:            h.iceServers(),
		MaxWebRTCPeers:        h.cfg.WebRTCMaxPeers,
		Permission:            result.Session.Permission.String(),
		NoteID:                result.Session.NoteID,
		HeartbeatSeconds:      int(h.cfg.SessionHeartbeat.Seconds()),
		BlockLockLeaseSeconds: int(h.cfg.BlockLockLease.Seconds()),
		BlockLockRenewSeconds: int(h.cfg.BlockLockRenew.Seconds()),
	}
	if h.cfg.EphemeralBinaryEnabled {
		response.BinaryEphemeralVersion = 2
	}
	writeJSON(w, http.StatusOK, response)
}

// websocketURL is the address the client is told to dial for its socket.
//
// A configured WEBSOCKET_URL always wins: behind a proxy or a load balancer the
// public address cannot be inferred from the request, so a deployment must be
// able to state it. When it is empty the URL is derived from the request that
// just arrived, which is what keeps local development working across network
// changes — the browser is sent back to the exact host it reached, whether that
// is localhost or whichever LAN address the machine holds today, with no
// configuration to update.
//
// Deriving from the Host header is safe here because the answer only ever goes
// back to the caller that supplied it: a forged Host redirects that client to
// itself and nobody else, and the ticket it carries is single-use.
func (h *Handlers) websocketURL(r *http.Request) string {
	if h.cfg.WebSocketURL != "" {
		return h.cfg.WebSocketURL
	}
	if r == nil || r.Host == "" {
		return ""
	}

	scheme := "ws"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "wss"
	}
	return scheme + "://" + r.Host + "/ws"
}

// iceServers builds the ICE configuration handed to an authenticated client.
//
// Served from here rather than from frontend configuration because TURN
// credentials are secrets: putting them in NEXT_PUBLIC_* would publish relay
// access to anyone who opened the bundle.
func (h *Handlers) iceServers() []ICEServer {
	servers := make([]ICEServer, 0, 2)

	if len(h.cfg.StunURLs) > 0 {
		servers = append(servers, ICEServer{URLs: h.cfg.StunURLs})
	}
	if len(h.cfg.TurnURLs) > 0 && h.cfg.TurnUsername != "" {
		servers = append(servers, ICEServer{
			URLs:       h.cfg.TurnURLs,
			Username:   h.cfg.TurnUsername,
			Credential: h.cfg.TurnCredential,
		})
	}
	return servers
}

// ── internal control ────────────────────────────────────────────────────────

type revokeSessionRequest struct {
	SessionID string `json:"sessionId"`
}

type updatePermissionRequest struct {
	SessionID  string `json:"sessionId"`
	Permission string `json:"permission"`
}

// RevokeSession ends one session immediately.
func (h *Handlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authenticateInternal(w, r)
	if !ok {
		return
	}

	var request revokeSessionRequest
	if err := json.Unmarshal(body, &request); err != nil || request.SessionID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "sessionId is required.")
		return
	}

	removed, err := h.sessions.RevokeSession(request.SessionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "sessionId is required.")
		return
	}

	// Removing the session record is not enough — an already-open socket would
	// keep relaying. Revocation has to reach the live connections too.
	disconnected := h.rooms.DisconnectSession(request.SessionID, "session revoked")

	writeJSON(w, http.StatusOK, map[string]any{
		"revoked":      removed,
		"disconnected": disconnected,
	})
}

// UpdateSessionPermission changes a live session's permission in place.
func (h *Handlers) UpdateSessionPermission(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authenticateInternal(w, r)
	if !ok {
		return
	}

	var request updatePermissionRequest
	if err := json.Unmarshal(body, &request); err != nil || request.SessionID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "sessionId and permission are required.")
		return
	}

	permission, err := domain.ParsePermission(request.Permission)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PERMISSION", "Unrecognised permission.")
		return
	}

	if err := h.sessions.UpdateSessionPermission(request.SessionID, permission); err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{"updated": false})
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "Could not update permission.")
		return
	}

	// Applied to live connections in place, so a demotion takes effect without
	// dropping the socket the user is drawing on.
	applied := h.rooms.ApplyPermission(request.SessionID, permission)

	writeJSON(w, http.StatusOK, map[string]any{"updated": true, "connections": applied})
}

// RevokeUserFromNote ends every session a user holds on a note, reading both
// ids from the request path.
func (h *Handlers) RevokeUserFromNote(w http.ResponseWriter, r *http.Request) {
	noteID := r.PathValue("noteId")
	userID := r.PathValue("userId")

	_, ok := h.authenticateInternal(w, r)
	if !ok {
		return
	}

	removed, err := h.sessions.RevokeUserFromNote(noteID, userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "noteId and userId are required.")
		return
	}

	disconnected := h.rooms.DisconnectUserFromNote(noteID, userID, "access revoked")

	writeJSON(w, http.StatusOK, map[string]any{
		"revokedSessions": removed,
		"disconnected":    disconnected,
	})
}

// authenticateInternal reads and verifies a signed control request, returning
// the body so the handler can decode it — the body must be read here because
// the signature covers its hash, and it can only be consumed once.
func (h *Handlers) authenticateInternal(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !h.hmac.Configured() {
		// Refuse rather than fall open: an unconfigured control plane must not
		// be an unauthenticated one.
		writeError(w, http.StatusServiceUnavailable, "CONTROL_DISABLED", "Internal control is not configured.")
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxControlBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "Could not read request body.")
		return nil, false
	}

	if err := h.hmac.Validate(r, body, h.now()); err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "Request signature was rejected.")
		return nil, false
	}

	return body, true
}

// ── helpers ─────────────────────────────────────────────────────────────────

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
