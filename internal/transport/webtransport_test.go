package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/security"
	"mypol/go-realtime/internal/testsupport"
)

// selfSignedTLS builds a throwaway certificate for 127.0.0.1.
//
// QUIC has no unencrypted mode, so unlike the WebSocket tests there is no way to
// exercise this without real TLS — the certificate is part of the fixture.
func selfSignedTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{http3.NextProtoH3},
	}, pool
}

type wtHarness struct {
	addr     string
	pool     *x509.CertPool
	keys     *testsupport.KeyPair
	sessions *application.SessionService
	rooms    *application.RoomService
	server   *webtransport.Server
}

func newWTHarness(t *testing.T) *wtHarness {
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
		return "wt-" + time.Now().Format("150405.000000000") + "-" + string(rune('a'+counter%26))
	}

	rooms := application.NewRoomService(infrastructure.NewMemoryRoomStore(), newID, clock)
	tlsConfig, pool := selfSignedTLS(t)

	// Port 0 lets the OS pick, so parallel test runs cannot collide.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &webtransport.Server{
		H3: &http3.Server{TLSConfig: tlsConfig},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/wt", ServeWebTransport(server, WebTransportDeps{
		Sessions:       sessions,
		Rooms:          rooms,
		AllowedOrigins: []string{"http://localhost:3000"},
		RateLimits: security.RateLimitSettings{
			EphemeralPerSecond: 160, EphemeralBurst: 240,
			ReliablePerSecond: 60, ReliableBurst: 120,
			SignalingPerSecond: 30, SignalingBurst: 60,
		},
		EphemeralQueue: 64,
		ReliableQueue:  128,
		MaxDatagram:    1100,
		IdleTimeout:    5 * time.Second,
		NewID:          newID,
		Now:            clock,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Health:         &Health{},
	}))
	server.H3.Handler = mux

	go func() { _ = server.Serve(conn) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = conn.Close()
	})

	return &wtHarness{
		addr:     conn.LocalAddr().String(),
		pool:     pool,
		keys:     keys,
		sessions: sessions,
		rooms:    rooms,
		server:   server,
	}
}

func (h *wtHarness) ticket(t *testing.T, in testsupport.ClaimsInput) string {
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

// dial opens a WebTransport session and its control stream, mirroring what the
// browser adapter does.
func (h *wtHarness) dial(t *testing.T, ticket string) (*webtransport.Session, *webtransport.Stream) {
	t.Helper()

	dialer := &webtransport.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := "https://" + h.addr + "/wt?ticket=" + ticket
	_, session, err := dialer.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	// The server waits for this stream, so write something to make it visible.
	writeFrame(t, stream, `{"v":2,"event":"presence.hello","payload":{}}`)

	t.Cleanup(func() { _ = session.CloseWithError(0, "test over") })
	return session, stream
}

func writeFrame(t *testing.T, w io.Writer, payload string) {
	t.Helper()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := w.Write(append(header, payload...)); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readFrame(t *testing.T, r io.Reader) *domain.Envelope {
	t.Helper()
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	var envelope domain.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return &envelope
}

// ── admission ───────────────────────────────────────────────────────────────

func TestWebTransportRequiresATicket(t *testing.T) {
	h := newWTHarness(t)

	dialer := &webtransport.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, _, err := dialer.Dial(ctx, "https://"+h.addr+"/wt", nil)
	if err == nil && response != nil && response.StatusCode < 400 {
		t.Fatal("a session without a ticket must be refused")
	}
}

func TestWebTransportRejectsASpentTicket(t *testing.T) {
	h := newWTHarness(t)
	ticket := h.ticket(t, testsupport.ClaimsInput{})
	h.dial(t, ticket)

	dialer := &webtransport.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.pool, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, _, err := dialer.Dial(ctx, "https://"+h.addr+"/wt?ticket="+ticket, nil)
	if err == nil && response != nil && response.StatusCode < 400 {
		t.Fatal("a replayed ticket must not open a second session")
	}
}

// ── reliable stream ─────────────────────────────────────────────────────────

func TestWebTransportDeliversRosterOnTheReliableStream(t *testing.T) {
	h := newWTHarness(t)
	_, stream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{}))

	envelope := readFrame(t, stream)

	if envelope.Event != application.EventRoomMembers {
		t.Fatalf("first frame = %q, want room.members", envelope.Event)
	}
	if envelope.V != domain.EnvelopeVersion {
		t.Errorf("envelope version = %d", envelope.V)
	}
}

func TestWebTransportRelaysReliableTrafficBetweenSessions(t *testing.T) {
	h := newWTHarness(t)

	_, firstStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s1"}))
	readFrame(t, firstStream) // roster

	_, secondStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s2"}))
	readFrame(t, secondStream) // roster

	readFrame(t, firstStream) // presence.joined for the second session

	writeFrame(t, secondStream, `{"v":2,"event":"ink.ended","payload":{"strokeId":"s","committed":true}}`)

	envelope := readFrame(t, firstStream)
	if envelope.Event != "ink.ended" {
		t.Fatalf("event = %q, want ink.ended", envelope.Event)
	}
	// Identity is stamped by the server, never taken from the client's claim.
	if envelope.ActorID == nil || *envelope.ActorID == "" {
		t.Error("actorId should be stamped by the server")
	}
	if envelope.Origin == nil || *envelope.Origin == "" {
		t.Error("origin should be the sender's connection id")
	}
}

// ── datagrams ───────────────────────────────────────────────────────────────

// The whole point of WebTransport: previews take the lossy path, so they cannot
// head-of-line block behind reliable traffic.
func TestWebTransportSendsPreviewsAsDatagrams(t *testing.T) {
	h := newWTHarness(t)

	firstSession, firstStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s1"}))
	readFrame(t, firstStream)

	_, secondStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s2"}))
	readFrame(t, secondStream)
	readFrame(t, firstStream) // presence.joined

	writeFrame(t, secondStream, `{"v":2,"event":"cursor.moved","payload":{"pageId":"p","x":42,"y":7}}`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload, err := firstSession.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("receive datagram: %v", err)
	}

	var envelope domain.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode datagram: %v", err)
	}
	if envelope.Event != "cursor.moved" {
		t.Fatalf("datagram event = %q, want cursor.moved", envelope.Event)
	}
}

// A client may send previews as datagrams too; the server must accept both.
func TestWebTransportAcceptsInboundDatagrams(t *testing.T) {
	h := newWTHarness(t)

	firstSession, firstStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s1"}))
	readFrame(t, firstStream)

	secondSession, secondStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s2"}))
	readFrame(t, secondStream)
	readFrame(t, firstStream)

	if err := secondSession.SendDatagram(
		[]byte(`{"v":2,"event":"cursor.moved","payload":{"pageId":"p","x":9,"y":9}}`),
	); err != nil {
		t.Fatalf("send datagram: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload, err := firstSession.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("receive datagram: %v", err)
	}
	if !json.Valid(payload) {
		t.Fatal("relayed datagram should be valid json")
	}
}

// ── permission ──────────────────────────────────────────────────────────────

// The permission rule must hold on both transports; enforcing it only for
// WebSocket would make choosing WebTransport a bypass.
func TestWebTransportEnforcesPermissionToo(t *testing.T) {
	h := newWTHarness(t)

	_, editorStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s1", Permission: "edit"}))
	readFrame(t, editorStream)

	_, viewerStream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{SessionID: "s2", Permission: "view"}))
	readFrame(t, viewerStream)
	readFrame(t, editorStream) // presence.joined

	// Ink from a viewer is dropped; the following reliable event is not.
	// (auth.refresh would not do here — it is handled by the server, not relayed.)
	writeFrame(t, viewerStream, `{"v":2,"event":"ink.ended","payload":{"strokeId":"x"}}`)
	writeFrame(t, viewerStream, `{"v":2,"event":"yjs.update","payload":{}}`)

	envelope := readFrame(t, editorStream)
	if envelope.Event != "yjs.update" {
		t.Fatalf("event = %q — a viewer's ink must not be relayed", envelope.Event)
	}
}
