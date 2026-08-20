package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/config"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/security"
	"mypol/go-realtime/internal/transport"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	publicKeyPEM, err := os.ReadFile(cfg.CanvasJWTPublicKeyFile)
	if err != nil {
		return err
	}

	validator, err := security.NewCanvasJWTValidator(
		publicKeyPEM, cfg.CanvasJWTIssuer, cfg.CanvasJWTAudience, cfg.CanvasJWTLeeway)
	if err != nil {
		return err
	}

	sessionStore := infrastructure.NewMemorySessionStore()
	ticketStore := infrastructure.NewMemoryTicketStore()
	sessions := application.NewSessionService(
		sessionStore, ticketStore, validator, cfg.ConnectionTicketTTL, time.Now)

	hmacValidator := security.NewHMACValidator(
		security.HMACKey{KeyID: cfg.InternalHMACCurrentKeyID, Secret: cfg.InternalHMACCurrentSecret},
		security.HMACKey{KeyID: cfg.InternalHMACPreviousKeyID, Secret: cfg.InternalHMACPreviousSecret},
		cfg.InternalHMACMaxClockSkew,
	)
	if !hmacValidator.Configured() {
		logger.Warn("internal control plane is disabled; no HMAC key configured")
	}

	rooms := application.NewRoomService(
		infrastructure.NewMemoryRoomStore(), newID, time.Now)

	health := &transport.Health{}
	handlers := transport.NewHandlers(sessions, rooms, hmacValidator, cfg, health, time.Now)

	websocketHandler := transport.ServeWebSocket(transport.WebSocketDeps{
		Sessions:       sessions,
		Rooms:          rooms,
		AllowedOrigins: cfg.AllowedOrigins,
		RateLimits: security.RateLimitSettings{
			EphemeralPerSecond: cfg.EphemeralRatePerConnection,
			EphemeralBurst:     cfg.EphemeralBurstPerConnection,
			ReliablePerSecond:  cfg.ReliableRatePerConnection,
			ReliableBurst:      cfg.ReliableBurstPerConnection,
			SignalingPerSecond: cfg.SignalingRatePerConnection,
			SignalingBurst:     cfg.SignalingBurstPerConnection,
		},
		EphemeralQueue: cfg.EphemeralQueueSize,
		ReliableQueue:  cfg.ReliableQueueSize,
		IdleTimeout:    cfg.SessionIdleTimeout,
		NewID:          newID,
		Now:            time.Now,
		Logger:         logger,
		Health:         health,
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           transport.NewRouter(handlers, cfg.AllowedOrigins, websocketHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sweepLoop(ctx, sessions, cfg, logger)

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("realtime service listening", "addr", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
	}

	// Fail readiness first so the load balancer stops sending new work, then
	// give in-flight requests the grace period to finish.
	logger.Info("draining")
	health.StartDraining()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

// newID mints ids for connections and server-generated envelopes. Random rather
// than sequential so a connection id reveals nothing about server load or
// another client's identity.
func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return time.Now().Format("20060102150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

// sweepLoop removes expired tickets and dead sessions on a fixed cadence, so
// abandoned bootstraps cannot grow the in-memory stores without bound.
func sweepLoop(ctx context.Context, sessions *application.SessionService, cfg *config.Config, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.ConnectionTicketSweep)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickets := sessions.SweepTickets()
			expired := sessions.SweepSessions(cfg.SessionIdleTimeout)
			if tickets > 0 || expired > 0 {
				logger.Debug("swept", "tickets", tickets, "sessions", expired)
			}
		}
	}
}
