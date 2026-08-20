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

	EphemeralQueueSize int
	ReliableQueueSize  int

	EphemeralRatePerConnection  float64
	EphemeralBurstPerConnection float64
	ReliableRatePerConnection   float64
	ReliableBurstPerConnection  float64
	SignalingRatePerConnection  float64
	SignalingBurstPerConnection float64

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

		EphemeralQueueSize: integer("EPHEMERAL_QUEUE_SIZE", 64),
		ReliableQueueSize:  integer("RELIABLE_QUEUE_SIZE", 128),

		// Sustained ephemeral rate sits above 120/s deliberately: ULTRA-profile
		// batching approaches 125 batches per second, so a tighter ceiling would
		// throttle legitimate drawing.
		EphemeralRatePerConnection:  float64(integer("EPHEMERAL_RATE_PER_CONNECTION", 160)),
		EphemeralBurstPerConnection: float64(integer("EPHEMERAL_BURST_PER_CONNECTION", 240)),
		ReliableRatePerConnection:   float64(integer("RELIABLE_RATE_PER_CONNECTION", 60)),
		ReliableBurstPerConnection:  float64(integer("RELIABLE_BURST_PER_CONNECTION", 120)),
		SignalingRatePerConnection:  float64(integer("SIGNALING_RATE_PER_CONNECTION", 30)),
		SignalingBurstPerConnection: float64(integer("SIGNALING_BURST_PER_CONNECTION", 60)),

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
