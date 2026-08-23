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

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/config"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/observability"
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
	rooms.SetMaxWebRTCPeers(cfg.WebRTCMaxPeers)

	locks := application.NewBlockLockService(
		infrastructure.NewMemoryLockStore(),
		application.BlockLockSettings{
			Lease:         cfg.BlockLockLease,
			MaxPerSession: cfg.MaxActiveBlockLocksPerSess,
		},
		time.Now)

	health := &transport.Health{}
	handlers := transport.NewHandlers(sessions, rooms, hmacValidator, cfg, health, time.Now)

	interest := application.NewInterestService(infrastructure.NewMemoryInterestIndex())
	rooms.SetInterest(interest, handlers.Metrics())

	websocketHandler := transport.ServeWebSocket(transport.WebSocketDeps{
		Sessions:       sessions,
		Rooms:          rooms,
		Locks:          locks,
		Interest:       interest,
		Metrics:        handlers.Metrics(),
		AllowedOrigins: cfg.AllowedOrigins,
		RateLimits:     rateLimits(cfg),
		EphemeralQueue: cfg.EphemeralQueueSize,
		ReliableQueue:  cfg.ReliableQueueSize,
		IdleTimeout:    cfg.SessionIdleTimeout,
		NewID:          newID,
		Now:            time.Now,
		Logger:         logger,
		Health:         health,
	})

	// WebTransport needs its own HTTP/3 listener and its own mux: the /wt route
	// only exists on the QUIC side, while everything else stays on HTTP/1.1.
	var wtServer *webtransport.Server
	if cfg.WebTransportEnabled() {
		wtServer = &webtransport.Server{
			H3: &http3.Server{Addr: cfg.WebTransportAddr},
		}
		wtMux := http.NewServeMux()
		wtMux.HandleFunc("GET /wt", transport.ServeWebTransport(wtServer, transport.WebTransportDeps{
			Sessions:       sessions,
			Rooms:          rooms,
			Locks:          locks,
			Interest:       interest,
			Metrics:        handlers.Metrics(),
			AllowedOrigins: cfg.AllowedOrigins,
			RateLimits:     rateLimits(cfg),
			EphemeralQueue: cfg.EphemeralQueueSize,
			ReliableQueue:  cfg.ReliableQueueSize,
			MaxDatagram:    cfg.MaxDatagramBytes,
			IdleTimeout:    cfg.SessionIdleTimeout,
			NewID:          newID,
			Now:            time.Now,
			Logger:         logger,
			Health:         health,
		}))
		wtServer.H3.Handler = wtMux

		go func() {
			logger.Info("webtransport listening", "addr", cfg.WebTransportAddr)
			if err := wtServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
				// Not fatal: WebSocket is still serving, so the canvas degrades
				// to the slower path rather than the service failing to run.
				logger.Error("webtransport stopped", "error", err)
			}
		}()
	} else {
		logger.Info("webtransport disabled; set WEBTRANSPORT_ADDR, TLS_CERT_FILE and TLS_KEY_FILE to enable")
	}

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           transport.NewRouter(handlers, cfg.AllowedOrigins, websocketHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sweepLoop(ctx, sessions, cfg, handlers.Metrics(), logger)
	go expireLocks(ctx, locks, rooms, handlers.Metrics(), cfg.BlockLockSweep)

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

	// Fail readiness first so the load balancer stops sending new work. Existing
	// canvas transports get one server.draining control frame, their bounded
	// reliable queues are given the configured grace period, then they close and
	// reconnect against the replacement instance.
	logger.Info("draining")
	health.StartDraining()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()

	serverShutdown := make(chan error, 1)
	go func() { serverShutdown <- server.Shutdown(shutdownCtx) }()

	connections := rooms.BeginDrain(cfg.ShutdownGrace)
	flushed := rooms.WaitForReliableDrain(shutdownCtx, 10*time.Millisecond)
	closed := rooms.CloseAll("server draining")
	logger.Info("drain complete", "connections", connections, "flushed", flushed, "closed", closed)

	// HTTP/3 has its own listener. It keeps accepting datagrams independently of
	// net/http, so it must be closed explicitly after live sessions were asked to
	// reconnect and their reliable output had a bounded chance to flush.
	if wtServer != nil {
		_ = wtServer.Close()
	}

	return <-serverShutdown
}

// rateLimits builds the per-connection budgets. Shared by both transports so a
// client cannot get a looser allowance simply by choosing the other one.
func rateLimits(cfg *config.Config) security.RateLimitSettings {
	return security.RateLimitSettings{
		EphemeralPerSecond: cfg.EphemeralRatePerConnection,
		EphemeralBurst:     cfg.EphemeralBurstPerConnection,
		ReliablePerSecond:  cfg.ReliableRatePerConnection,
		ReliableBurst:      cfg.ReliableBurstPerConnection,
		SignalingPerSecond: cfg.SignalingRatePerConnection,
		SignalingBurst:     cfg.SignalingBurstPerConnection,
	}
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

// expireLocks reclaims lapsed geometry leases and tells each room.
//
// The announcement is the point, not the reclamation. A client whose renew
// stopped landing has no way to know its lease is gone, and its peers have no
// way to know the block is free — so both keep believing something that is no
// longer true until the server says otherwise.
func expireLocks(
	ctx context.Context,
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
	interval time.Duration,
) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expired := locks.SweepExpired()
			for _, lock := range expired {
				// Everyone, the former holder included: it is the party that
				// most needs to stop dragging.
				rooms.Announce(lock.NoteID, "", application.EventLockExpired,
					application.PublicHolderOf(lock))
			}
			if len(expired) > 0 {
				metrics.BlockLocksActive.Store(int64(locks.ActiveLocks()))
			}
		}
	}
}

// sweepLoop removes expired tickets and dead sessions on a fixed cadence, so
// abandoned bootstraps cannot grow the in-memory stores without bound.
func sweepLoop(ctx context.Context, sessions *application.SessionService, cfg *config.Config, metrics *observability.Metrics, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.ConnectionTicketSweep)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickets := sessions.SweepTickets()
			expired := sessions.SweepSessions(cfg.SessionIdleTimeout)
			if metrics != nil && tickets > 0 {
				metrics.TicketsExpired.Add(int64(tickets))
			}
			if tickets > 0 || expired > 0 {
				logger.Debug("swept", "tickets", tickets, "sessions", expired)
			}
		}
	}
}
