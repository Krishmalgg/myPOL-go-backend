package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the service's runtime configuration, read from the environment.
//
// Secrets are never defaulted to a usable value: an unset HMAC secret leaves the
// internal control plane disabled rather than open, and an unset public key path
// fails startup rather than accepting unverified tokens.
type Config struct {
	HTTPAddr       string
	AllowedOrigins []string

	CanvasJWTIssuer        string
	CanvasJWTAudience      string
	CanvasJWTPublicKeyFile string
	CanvasJWTLeeway        time.Duration

	InternalHMACCurrentKeyID   string
	InternalHMACCurrentSecret  string
	InternalHMACPreviousKeyID  string
	InternalHMACPreviousSecret string
	InternalHMACMaxClockSkew   time.Duration

	ConnectionTicketTTL   time.Duration
	ConnectionTicketSweep time.Duration
	SessionHeartbeat      time.Duration
	SessionIdleTimeout    time.Duration

	// WebSocketURL and WebTransportURL are advertised to clients at bootstrap.
	// WebTransport is omitted from the response while empty, which is how a
	// client learns the path is unavailable.
	WebSocketURL    string
	WebTransportURL string

	WebRTCMaxPeers int

	// ICE configuration is served from the authenticated bootstrap rather than
	// baked into frontend JavaScript, so TURN credentials are never public.
	StunURLs       []string
	TurnURLs       []string
	TurnUsername   string
	TurnCredential string

	// WebTransport runs on its own HTTP/3 listener. Empty disables it, which is
	// the default: it needs TLS certificates that a plain WebSocket does not.
	WebTransportAddr string
	TLSCertFile      string
	TLSKeyFile       string
	MaxDatagramBytes int

	EphemeralQueueSize int
	ReliableQueueSize  int
	// Advertised at bootstrap. Zero keeps clients on JSON, which makes a
	// rolling frontend/server deploy safe instead of assuming binary support.
	EphemeralBinaryEnabled bool

	EphemeralRatePerConnection  float64
	EphemeralBurstPerConnection float64
	ReliableRatePerConnection   float64
	ReliableBurstPerConnection  float64
	SignalingRatePerConnection  float64
	SignalingBurstPerConnection float64

	// Bootstrap limits are per authenticated user first, with a deliberately
	// generous per-IP ceiling: many legitimate users share one NAT address.
	BootstrapRatePerUserPerMinute float64
	BootstrapBurstPerUser         float64
	BootstrapRatePerIPPerMinute   float64
	BootstrapBurstPerIP           float64

	// Block geometry leases. The renew interval is advisory — the client uses
	// it to decide how often to refresh — while the lease is what the server
	// actually enforces. Renewing at well under half the lease means a single
	// lost renew does not end a gesture in progress.
	BlockLockLease             time.Duration
	BlockLockRenew             time.Duration
	MaxActiveBlockLocksPerSess int
	BlockLockSweep             time.Duration

	ShutdownGrace time.Duration
}

// Load reads configuration from the environment, applying the plan's defaults.
func Load() (*Config, error) {
	cfg := &Config{
		HTTPAddr:       env("HTTP_ADDR", ":8080"),
		AllowedOrigins: splitAndTrim(env("ALLOWED_ORIGINS", "http://localhost:3000")),

		CanvasJWTIssuer:        env("CANVAS_JWT_ISSUER", "mypol-api"),
		CanvasJWTAudience:      env("CANVAS_JWT_AUDIENCE", "canvas-realtime"),
		CanvasJWTPublicKeyFile: env("CANVAS_JWT_PUBLIC_KEY_FILE", ""),
		CanvasJWTLeeway:        seconds("CANVAS_JWT_LEEWAY_SECONDS", 5),

		InternalHMACCurrentKeyID:   env("INTERNAL_HMAC_CURRENT_KEY_ID", ""),
		InternalHMACCurrentSecret:  env("INTERNAL_HMAC_CURRENT_SECRET", ""),
		InternalHMACPreviousKeyID:  env("INTERNAL_HMAC_PREVIOUS_KEY_ID", ""),
		InternalHMACPreviousSecret: env("INTERNAL_HMAC_PREVIOUS_SECRET", ""),
		InternalHMACMaxClockSkew:   seconds("INTERNAL_HMAC_MAX_CLOCK_SKEW_SECONDS", 30),

		ConnectionTicketTTL:   seconds("CONNECTION_TICKET_TTL_SECONDS", 30),
		ConnectionTicketSweep: seconds("CONNECTION_TICKET_SWEEP_SECONDS", 10),
		SessionHeartbeat:      seconds("SESSION_HEARTBEAT_SECONDS", 15),
		SessionIdleTimeout:    seconds("SESSION_IDLE_TIMEOUT_SECONDS", 45),

		WebSocketURL:    env("WEBSOCKET_URL", ""),
		WebTransportURL: env("WEBTRANSPORT_URL", ""),

		WebRTCMaxPeers: integer("WEBRTC_MAX_PEERS", 6),

		StunURLs:       splitAndTrim(env("STUN_URLS", "stun:stun.l.google.com:19302")),
		TurnURLs:       splitAndTrim(env("TURN_URLS", "")),
		TurnUsername:   env("TURN_USERNAME", ""),
		TurnCredential: env("TURN_CREDENTIAL", ""),

		WebTransportAddr: env("WEBTRANSPORT_ADDR", ""),
		TLSCertFile:      env("TLS_CERT_FILE", ""),
		TLSKeyFile:       env("TLS_KEY_FILE", ""),
		MaxDatagramBytes: integer("MAX_DATAGRAM_BYTES", 1100),

		EphemeralQueueSize:     integer("EPHEMERAL_QUEUE_SIZE", 64),
		ReliableQueueSize:      integer("RELIABLE_QUEUE_SIZE", 128),
		EphemeralBinaryEnabled: boolean("EPHEMERAL_BINARY_ENABLED", true),

		// One connection's ephemeral streams share this bucket, so the ceiling is
		// the sum of them, not the largest. A single ULTRA-profile drawer emits
		// ink at 8ms and cursor at 16ms — about 188/s together, and about 313/s
		// if a transform drag overlaps. The former ceiling of 160/s sat below
		// even the ordinary drawing case, so the burst drained after a few
		// seconds of continuous work and previews then vanished mid-stroke with
		// no error anywhere. Sized above the worst legitimate case; a runaway
		// client is orders of magnitude beyond this and is still caught.
		EphemeralRatePerConnection:  float64(integer("EPHEMERAL_RATE_PER_CONNECTION", 360)),
		EphemeralBurstPerConnection: float64(integer("EPHEMERAL_BURST_PER_CONNECTION", 540)),
		// Erasing relays `ink.patch` here, coalesced by the client into roughly
		// 30 frames a second while a rub is in progress. Added to stroke commits,
		// transform commits and Yjs updates, the old 60/s left no margin on the
		// one class that may never be dropped.
		ReliableRatePerConnection:   float64(integer("RELIABLE_RATE_PER_CONNECTION", 120)),
		ReliableBurstPerConnection:  float64(integer("RELIABLE_BURST_PER_CONNECTION", 240)),
		SignalingRatePerConnection:  float64(integer("SIGNALING_RATE_PER_CONNECTION", 30)),
		SignalingBurstPerConnection: float64(integer("SIGNALING_BURST_PER_CONNECTION", 60)),

		BootstrapRatePerUserPerMinute: float64(integer("BOOTSTRAP_RATE_PER_USER_PER_MINUTE", 30)),
		BootstrapBurstPerUser:         float64(integer("BOOTSTRAP_BURST_PER_USER", 10)),
		// 600/min, not 10: a campus or office NAT carries hundreds of real users.
		BootstrapRatePerIPPerMinute: float64(integer("BOOTSTRAP_RATE_PER_IP_PER_MINUTE", 600)),
		BootstrapBurstPerIP:         float64(integer("BOOTSTRAP_BURST_PER_IP", 100)),

		BlockLockLease:             seconds("BLOCK_LOCK_LEASE_SECONDS", 5),
		BlockLockRenew:             seconds("BLOCK_LOCK_RENEW_SECONDS", 2),
		MaxActiveBlockLocksPerSess: integer("MAX_ACTIVE_BLOCK_LOCKS_PER_SESSION", 4),
		// Swept at half the renew interval so an expired lease is announced
		// within a frame or two of lapsing, not a second later.
		BlockLockSweep: time.Second,

		ShutdownGrace: seconds("SHUTDOWN_GRACE_SECONDS", 5),
	}

	if cfg.CanvasJWTPublicKeyFile == "" {
		return nil, errors.New("CANVAS_JWT_PUBLIC_KEY_FILE is required: without the .NET public key no token can be verified")
	}

	return cfg, nil
}

// InternalControlEnabled reports whether the internal control plane has a usable
// key. When false the internal endpoints reject every request.
func (c *Config) InternalControlEnabled() bool {
	return c.InternalHMACCurrentKeyID != "" && c.InternalHMACCurrentSecret != ""
}

// WebTransportEnabled reports whether HTTP/3 can actually be served. All three
// pieces are required: without certificates QUIC cannot start at all, so a
// half-configured deployment must stay on WebSocket rather than fail to boot.
func (c *Config) WebTransportEnabled() bool {
	return c.WebTransportAddr != "" && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func integer(key string, fallback int) int {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func boolean(key string, fallback bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func seconds(key string, fallback int) time.Duration {
	return time.Duration(integer(key, fallback)) * time.Second
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
