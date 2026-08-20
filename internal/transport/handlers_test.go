package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/config"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/security"
	"mypol/go-realtime/internal/testsupport"
)

const (
	testKeyID  = "hmac-2026-01"
	testSecret = "internal-secret"
)

type harness struct {
	router   http.Handler
	keys     *testsupport.KeyPair
	sessions *application.SessionService
	rooms    *application.RoomService
	health   *Health
	now      time.Time
}

func newHarness(t *testing.T, withHMAC bool) *harness {
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

	now := time.Now()
	clock := func() time.Time { return now }

	sessions := application.NewSessionService(
		infrastructure.NewMemorySessionStore(),
		infrastructure.NewMemoryTicketStore(),
		validator,
		30*time.Second,
		clock,
	)

	current := security.HMACKey{}
	if withHMAC {
		current = security.HMACKey{KeyID: testKeyID, Secret: testSecret}
	}
	hmac := security.NewHMACValidator(current, security.HMACKey{}, 30*time.Second)

	cfg := &config.Config{
		AllowedOrigins:   []string{"http://localhost:3000"},
		WebSocketURL:     "wss://realtime.example/ws",
		WebRTCMaxPeers:   6,
		SessionHeartbeat: 15 * time.Second,
	}

	rooms := application.NewRoomService(
		infrastructure.NewMemoryRoomStore(),
		func() string { return "msg-" + time.Now().Format("150405.000000000") },
		clock,
	)

	health := &Health{}
	handlers := NewHandlers(sessions, rooms, hmac, cfg, health, clock)

	return &harness{
		router:   NewRouter(handlers, cfg.AllowedOrigins, nil),
		keys:     keys,
		sessions: sessions,
		rooms:    rooms,
		health:   health,
		now:      now,
	}
}

func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	h.router.ServeHTTP(recorder, req)
	return recorder
}

func (h *harness) bootstrapRequest(t *testing.T, in testsupport.ClaimsInput) *http.Request {
	t.Helper()
	token, err := h.keys.Sign(testsupport.Claims(in))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func (h *harness) signedControl(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	timestamp := h.now.Unix()
	nonce := "nonce-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	signature := security.Sign(testSecret,
		security.CanonicalRequest(req.Method, path, timestamp, nonce, []byte(body)))

	req.Header.Set(security.HeaderServiceID, "mypol-api")
	req.Header.Set(security.HeaderKeyID, testKeyID)
	req.Header.Set(security.HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(security.HeaderNonce, nonce)
	req.Header.Set(security.HeaderSignature, signature)
	return req
}

// ── health ──────────────────────────────────────────────────────────────────

func TestHealthzAlwaysReportsAlive(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Code)
	}

	// Liveness stays true while draining: the process is up, it just should not
	// receive new traffic.
	h.health.StartDraining()
	if res := h.do(httptest.NewRequest(http.MethodGet, "/healthz", nil)); res.Code != http.StatusOK {
		t.Fatalf("healthz during drain = %d, want 200", res.Code)
	}
}

func TestReadyzFailsWhileDraining(t *testing.T) {
	h := newHarness(t, true)

	if res := h.do(httptest.NewRequest(http.MethodGet, "/readyz", nil)); res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Code)
	}

	h.health.StartDraining()
	if res := h.do(httptest.NewRequest(http.MethodGet, "/readyz", nil)); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz during drain = %d, want 503", res.Code)
	}
}

// ── bootstrap ───────────────────────────────────────────────────────────────

func TestBootstrapReturnsTheFullClientContract(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	var body BootstrapResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.SessionID == "" {
		t.Error("sessionId missing")
	}
	if body.ConnectionTicket == "" {
		t.Error("connectionTicket missing")
	}
	if body.TicketExpiresAt.IsZero() {
		t.Error("ticketExpiresAt missing")
	}
	if body.WebSocketURL != "wss://realtime.example/ws" {
		t.Errorf("websocketUrl = %q", body.WebSocketURL)
	}
	if body.MaxWebRTCPeers != 6 {
		t.Errorf("maxWebRtcPeers = %d, want 6", body.MaxWebRTCPeers)
	}
	if body.ICEServers == nil {
		t.Error("iceServers should be present, even when empty")
	}
	if body.Permission != "edit" {
		t.Errorf("permission = %q", body.Permission)
	}
}

// WebTransport is not configured in this phase, so the field must be absent
// rather than present-and-empty — that is how a client learns it is unavailable.
func TestBootstrapOmitsWebTransportUrlWhenUnconfigured(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))

	var raw map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["webTransportUrl"]; present {
		t.Error("webTransportUrl should be omitted when not configured")
	}
}

func TestBootstrapRequiresABearerToken(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
}

func TestBootstrapRejectsBadTokenWithoutLeakingWhy(t *testing.T) {
	h := newHarness(t, true)
	stranger, err := testsupport.NewKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	token, _ := stranger.Sign(testsupport.Claims(testsupport.ClaimsInput{}))

	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := h.do(req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
	// Telling the caller which check failed would help them forge the next one.
	for _, leak := range []string{"signature", "issuer", "audience", "expired", "crypto"} {
		if strings.Contains(strings.ToLower(res.Body.String()), leak) {
			t.Errorf("response leaks validation detail %q: %s", leak, res.Body.String())
		}
	}
}

func TestBootstrapRefusedWhileDraining(t *testing.T) {
	h := newHarness(t, true)
	h.health.StartDraining()

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.Code)
	}
}

func TestBootstrapTicketIsRedeemableExactlyOnce(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))
	var body BootstrapResponse
	_ = json.Unmarshal(res.Body.Bytes(), &body)

	if _, err := h.sessions.ConsumeTicket(body.ConnectionTicket); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := h.sessions.ConsumeTicket(body.ConnectionTicket); err == nil {
		t.Fatal("second consume must fail")
	}
}

// ── internal control ────────────────────────────────────────────────────────

func TestRevokeSessionRequiresAValidSignature(t *testing.T) {
	h := newHarness(t, true)

	unsigned := httptest.NewRequest(http.MethodPost, "/internal/v1/sessions/revoke",
		strings.NewReader(`{"sessionId":"s1"}`))
	if res := h.do(unsigned); res.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status = %d, want 401", res.Code)
	}

	tampered := h.signedControl(t, "/internal/v1/sessions/revoke", `{"sessionId":"s1"}`)
	tampered.Header.Set(security.HeaderSignature, strings.Repeat("0", 64))
	if res := h.do(tampered); res.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d, want 401", res.Code)
	}
}

func TestRevokeSessionEndsALiveSession(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))
	var bootstrapped BootstrapResponse
	_ = json.Unmarshal(res.Body.Bytes(), &bootstrapped)

	body := `{"sessionId":"` + bootstrapped.SessionID + `"}`
	revoke := h.do(h.signedControl(t, "/internal/v1/sessions/revoke", body))
	if revoke.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", revoke.Code, revoke.Body.String())
	}

	if _, ok := h.sessions.Session(bootstrapped.SessionID); ok {
		t.Error("session should be gone")
	}
}

func TestUpdatePermissionChangesALiveSession(t *testing.T) {
	h := newHarness(t, true)

	res := h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{}))
	var bootstrapped BootstrapResponse
	_ = json.Unmarshal(res.Body.Bytes(), &bootstrapped)

	body := `{"sessionId":"` + bootstrapped.SessionID + `","permission":"view"}`
	if got := h.do(h.signedControl(t, "/internal/v1/sessions/permission", body)); got.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", got.Code, got.Body.String())
	}

	session, ok := h.sessions.Session(bootstrapped.SessionID)
	if !ok {
		t.Fatal("session must survive a permission change")
	}
	if session.Permission.String() != "view" {
		t.Errorf("permission = %q, want view", session.Permission)
	}
}

func TestUpdatePermissionRejectsUnknownValue(t *testing.T) {
	h := newHarness(t, true)

	body := `{"sessionId":"whatever","permission":"root"}`
	res := h.do(h.signedControl(t, "/internal/v1/sessions/permission", body))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
}

func TestRevokeUserFromNoteEndsEveryTab(t *testing.T) {
	h := newHarness(t, true)

	for _, sid := range []string{"sid-a", "sid-b"} {
		h.do(h.bootstrapRequest(t, testsupport.ClaimsInput{
			UserID: "user-1", NoteID: "note-1", SessionID: sid,
		}))
	}

	path := "/internal/v1/notes/note-1/users/user-1/revoke"
	res := h.do(h.signedControl(t, path, `{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	var payload struct {
		RevokedSessions int `json:"revokedSessions"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &payload)
	if payload.RevokedSessions != 2 {
		t.Errorf("revokedSessions = %d, want 2", payload.RevokedSessions)
	}
}

// An unconfigured control plane must refuse, not fall open.
func TestInternalEndpointsRefuseWhenHMACUnconfigured(t *testing.T) {
	h := newHarness(t, false)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/sessions/revoke",
		strings.NewReader(`{"sessionId":"s1"}`))
	if res := h.do(req); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.Code)
	}
}

// ── cors / origin ───────────────────────────────────────────────────────────

func TestCORSEchoesOnlyAllowedOrigins(t *testing.T) {
	h := newHarness(t, true)

	allowed := httptest.NewRequest(http.MethodOptions, "/v1/sessions/bootstrap", nil)
	allowed.Header.Set("Origin", "http://localhost:3000")
	res := h.do(allowed)
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("allow-origin = %q", got)
	}

	// Reflecting an arbitrary Origin would defeat the allow-list entirely.
	stranger := httptest.NewRequest(http.MethodOptions, "/v1/sessions/bootstrap", nil)
	stranger.Header.Set("Origin", "https://evil.example")
	if got := h.do(stranger).Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no allow-origin for a stranger, got %q", got)
	}
}

// Internal control is server-to-server; no browser should be able to reach it.
func TestBrowserOriginCannotReachInternalPaths(t *testing.T) {
	h := newHarness(t, true)

	req := h.signedControl(t, "/internal/v1/sessions/revoke", `{"sessionId":"s1"}`)
	req.Header.Set("Origin", "http://localhost:3000")

	if res := h.do(req); res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.Code)
	}
}
