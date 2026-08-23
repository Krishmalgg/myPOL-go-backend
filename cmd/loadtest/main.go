// Command loadtest exercises the real canvas bootstrap and relay protocols.
// It is a development/load-test tool, not a production client.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
	"github.com/quic-go/quic-go"
	webtransport "github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/codec"
	"mypol/go-realtime/internal/domain"
)

const maxPayloadBytes = 256 * 1024

type options struct {
	baseURL, origin, privateKey, issuer, audience string
	transport, encoding, scenario                 string
	connections                                   int
	duration, commitEvery, connectRamp            time.Duration
	drainGrace                                    time.Duration
	previewRate, activeRatio                      float64
	activeDrawers, canvases, pages                int
	insecureTLS                                   bool
	report                                        string
}

type bootstrapResponse struct {
	SessionID        string `json:"sessionId"`
	ConnectionTicket string `json:"connectionTicket"`
	WebSocketURL     string `json:"websocketUrl"`
	WebTransportURL  string `json:"webTransportUrl"`
	NoteID           string `json:"noteId"`
	BinaryVersion    int    `json:"binaryEphemeralVersion"`
}

type assignment struct {
	userID, noteID, pageID string
	x, y                   float64
	active                 bool
}

type inboundFrame struct {
	binary bool
	data   []byte
}

type loadConnection interface {
	write(context.Context, []byte, bool, bool) (int, error)
	read(context.Context) (inboundFrame, error)
	close() error
}

type wsConnection struct{ conn *websocket.Conn }

func (c *wsConnection) write(ctx context.Context, data []byte, _ bool, binaryFrame bool) (int, error) {
	kind := websocket.MessageText
	if binaryFrame {
		kind = websocket.MessageBinary
	}
	if err := c.conn.Write(ctx, kind, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *wsConnection) read(ctx context.Context) (inboundFrame, error) {
	kind, data, err := c.conn.Read(ctx)
	if err != nil {
		return inboundFrame{}, err
	}
	return inboundFrame{binary: kind == websocket.MessageBinary, data: data}, nil
}

func (c *wsConnection) close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "load complete")
}

// WebTransport uses datagrams for previews and one bidirectional stream for
// reliable frames, matching internal/transport/wt_connection.go.
type wtConnection struct {
	session *webtransport.Session
	stream  *webtransport.Stream
	writeMu sync.Mutex
	frames  chan inboundFrame
	done    chan struct{}
	once    sync.Once
}

func newWTConnection(session *webtransport.Session, stream *webtransport.Stream) *wtConnection {
	c := &wtConnection{session: session, stream: stream, frames: make(chan inboundFrame, 1024), done: make(chan struct{})}
	go c.readDatagrams()
	go c.readStream()
	return c
}

func (c *wtConnection) readDatagrams() {
	for {
		data, err := c.session.ReceiveDatagram(context.Background())
		if err != nil {
			c.finish()
			return
		}
		c.push(inboundFrame{binary: true, data: data})
	}
}

func (c *wtConnection) readStream() {
	for {
		var prefix [4]byte
		if _, err := io.ReadFull(c.stream, prefix[:]); err != nil {
			c.finish()
			return
		}
		size := binary.BigEndian.Uint32(prefix[:])
		if size == 0 || size > maxPayloadBytes {
			c.finish()
			return
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(c.stream, data); err != nil {
			c.finish()
			return
		}
		c.push(inboundFrame{data: data})
	}
}

func (c *wtConnection) push(frame inboundFrame) {
	select {
	case <-c.done:
		return
	case c.frames <- frame:
	default:
		// The runner has a bounded receive queue just like the server.
	}
}

func (c *wtConnection) finish() { c.once.Do(func() { close(c.done) }) }

func (c *wtConnection) write(ctx context.Context, data []byte, ephemeral, _ bool) (int, error) {
	if ephemeral {
		if err := c.session.SendDatagram(data); err != nil {
			return 0, err
		}
		return len(data), nil
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = ctx
	if _, err := c.stream.Write(frame); err != nil {
		return 0, err
	}
	return len(frame), nil
}

func (c *wtConnection) read(ctx context.Context) (inboundFrame, error) {
	select {
	case <-c.done:
		return inboundFrame{}, io.EOF
	case frame := <-c.frames:
		return frame, nil
	case <-ctx.Done():
		return inboundFrame{}, ctx.Err()
	}
}

func (c *wtConnection) close() error {
	c.finish()
	return c.session.CloseWithError(0, "load complete")
}

type counters struct {
	attempted, opened, failures, closed, reconnects          atomic.Int64
	sendMessages, sendBytes, receiveMessages, receiveBytes   atomic.Int64
	previewSent, previewReceived, commitSent, commitReceived atomic.Int64
	expectedCommitDeliveries, unexpectedMessages             atomic.Int64
}

type metricsSnapshot struct {
	ActiveSessions             int64   `json:"activeSessions"`
	ActiveConnections          int64   `json:"activeConnections"`
	ActiveRooms                int64   `json:"activeRooms"`
	MessagesIn                 int64   `json:"messagesInTotal"`
	MessagesOut                int64   `json:"messagesOutTotal"`
	IncomingBytes              int64   `json:"incomingBytesTotal"`
	OutgoingBytes              int64   `json:"outgoingBytesTotal"`
	DroppedEphemeral           int64   `json:"droppedEphemeralTotal"`
	ReliableOverflow           int64   `json:"reliableOverflowTotal"`
	ReliableQueueDepthMax      int64   `json:"reliableQueueDepthMax"`
	EphemeralQueueDepthMax     int64   `json:"ephemeralQueueDepthMax"`
	InterestRecipientsPerEvent float64 `json:"interestRecipientsPerEvent"`
	InterestFiltered           int64   `json:"interestFilteredRecipientsTotal"`
}

type runState struct {
	counters
	opts                      options
	assignments               []assignment
	sentMu                    sync.RWMutex
	sentAt                    map[string]map[uint64]time.Time
	latMu                     sync.Mutex
	latencies                 []float64
	serverBefore, serverAfter metricsSnapshot
	serverError               string
	stopSending               chan struct{}
}

type virtualUser struct {
	assignment assignment
	bootstrap  bootstrapResponse
	conn       loadConnection
	cleanup    func()
	seq        atomic.Uint64
}

type report struct {
	GeneratedAt string         `json:"generatedAt"`
	GoVersion   string         `json:"goVersion"`
	Run         runReport      `json:"run"`
	Observed    observedReport `json:"observed"`
	Server      serverReport   `json:"server"`
	Notes       []string       `json:"notes"`
}

type runReport struct {
	BaseURL, Transport, Encoding, Scenario string
	Connections                            int
	Duration                               string
	PreviewRate                            float64
	ActiveRatio                            float64
	ActiveDrawers, Canvases, Pages         int
}

type observedReport struct {
	ConnectionsAttempted, ConnectionsOpened, ConnectionFailures, ConnectionsClosed, Reconnects int64
	LocalSendMessages, LocalReceiveMessages, LocalSendBytes, LocalReceiveBytes                 int64
	PreviewSent, PreviewReceived, CommitsSent, CommitsReceived                                 int64
	ExpectedCommitDeliveries, UnexpectedMessages                                               int64
	P50PreviewLatencyMs, P95PreviewLatencyMs, P99PreviewLatencyMs                              float64
	MessagesPerSecond, IncomingBytesPerSecond, OutgoingBytesPerSecond, BytesPerUser            float64
	FinalCommitDeliveryRate                                                                    float64
}

type serverReport struct {
	MetricsBefore                                                       metricsSnapshot `json:"metricsBefore"`
	MetricsAfter                                                        metricsSnapshot `json:"metricsAfter"`
	MessagesPerSecond, IncomingBytesPerSecond, OutgoingBytesPerSecond   float64
	RecipientsPerEvent                                                  float64
	DroppedEphemeral, ReliableOverflow, InterestFiltered, QueueDepthMax int64
	MetricsError                                                        string   `json:"metricsError,omitempty"`
	CPUPercent                                                          *float64 `json:"cpuPercent,omitempty"`
	RAMBytes                                                            *int64   `json:"ramBytes,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "loadtest:", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseOptions()
	if err := validateOptions(opts); err != nil {
		return err
	}
	key, err := loadPrivateKey(opts.privateKey)
	if err != nil {
		return err
	}
	state := &runState{opts: opts, assignments: makeAssignments(opts), sentAt: make(map[string]map[uint64]time.Time), latencies: make([]float64, 0, 200_000), stopSending: make(chan struct{})}
	state.serverBefore, state.serverError = fetchMetrics(opts.baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), opts.duration+opts.drainGrace+2*time.Minute)
	defer cancel()

	users := make([]*virtualUser, opts.connections)
	var connectWG sync.WaitGroup
	for i := range users {
		connectWG.Add(1)
		go func(index int) {
			defer connectWG.Done()
			state.attempted.Add(1)
			user, openErr := openVirtualUser(ctx, opts, state.assignments[index], key)
			if openErr != nil {
				state.failures.Add(1)
				return
			}
			users[index] = user
			state.opened.Add(1)
		}(i)
		if opts.connectRamp > 0 {
			time.Sleep(opts.connectRamp)
		}
	}
	connectWG.Wait()
	opened := make([]*virtualUser, 0, len(users))
	connectedAssignments := make([]assignment, 0, len(users))
	for _, user := range users {
		if user != nil {
			opened = append(opened, user)
			connectedAssignments = append(connectedAssignments, user.assignment)
		}
	}
	state.assignments = connectedAssignments
	if len(opened) == 0 {
		return errors.New("no virtual users connected; check key, server address, and bootstrap limits")
	}

	start := time.Now()
	var runWG sync.WaitGroup
	for _, user := range opened {
		runWG.Add(1)
		go func(u *virtualUser) { defer runWG.Done(); u.run(ctx, state, start) }(user)
	}
	timer := time.NewTimer(opts.duration)
	<-timer.C
	close(state.stopSending)
	time.Sleep(opts.drainGrace)
	cancel()
	runWG.Wait()
	for _, user := range opened {
		_ = user.close()
		state.closed.Add(1)
	}
	state.serverAfter, state.serverError = fetchMetrics(opts.baseURL)
	result := makeReport(state, start, time.Now())
	if opts.report != "" {
		if err := writeReport(opts.report, result); err != nil {
			return err
		}
	}
	printSummary(result)
	return nil
}

func parseOptions() options {
	var o options
	flag.StringVar(&o.baseURL, "base-url", "http://127.0.0.1:8080", "Go realtime HTTP base URL")
	flag.StringVar(&o.origin, "origin", "http://localhost:3000", "Origin header")
	flag.StringVar(&o.privateKey, "private-key", "keys/canvas-private.pem", "development ES256 PKCS#8 private key")
	flag.StringVar(&o.issuer, "issuer", "mypol-api", "Canvas JWT issuer")
	flag.StringVar(&o.audience, "audience", "canvas-realtime", "Canvas JWT audience")
	flag.StringVar(&o.transport, "transport", "websocket", "websocket or webtransport")
	flag.StringVar(&o.encoding, "encoding", "json", "json or binary previews")
	flag.StringVar(&o.scenario, "scenario", "hotspot", "distributed, mostly-viewing, multi-page, viewports, or hotspot")
	flag.IntVar(&o.connections, "connections", 100, "virtual users")
	flag.DurationVar(&o.duration, "duration", 15*time.Second, "measurement duration")
	flag.Float64Var(&o.previewRate, "preview-rate", 30, "previews per active drawer per second")
	flag.Float64Var(&o.activeRatio, "active-ratio", -1, "active ratio; -1 uses scenario default")
	flag.IntVar(&o.activeDrawers, "active-drawers", -1, "active drawer count; -1 uses ratio")
	flag.IntVar(&o.canvases, "canvases", 10, "note rooms for distributed scenario")
	flag.IntVar(&o.pages, "pages", 8, "logical pages")
	flag.DurationVar(&o.commitEvery, "commit-every", 3*time.Second, "reliable ink.commit interval; 0 disables")
	flag.DurationVar(&o.drainGrace, "drain-grace", 5*time.Second, "reliable delivery drain after preview generation stops")
	flag.DurationVar(&o.connectRamp, "connect-ramp", 0, "delay between connection starts")
	flag.BoolVar(&o.insecureTLS, "insecure-tls", true, "skip TLS verification for local WebTransport")
	flag.StringVar(&o.report, "report", "", "markdown output path; JSON is written beside it")
	flag.Parse()
	return o
}

func validateOptions(o options) error {
	if o.connections < 1 || o.connections > 10_000 {
		return errors.New("connections must be between 1 and 10000")
	}
	if o.duration <= 0 || o.drainGrace < 0 || o.previewRate < 0 || o.canvases < 1 || o.pages < 1 {
		return errors.New("duration, canvases, pages, and preview-rate must be positive")
	}
	if o.activeRatio < -1 || o.activeRatio > 1 {
		return errors.New("active-ratio must be -1 or between 0 and 1")
	}
	if o.activeDrawers < -1 || o.activeDrawers > o.connections {
		return errors.New("active-drawers must be -1 or within connections")
	}
	if o.transport != "websocket" && o.transport != "webtransport" {
		return errors.New("transport must be websocket or webtransport; WebRTC requires a browser ICE run")
	}
	if o.encoding != "json" && o.encoding != "binary" {
		return errors.New("encoding must be json or binary")
	}
	return nil
}

func makeAssignments(o options) []assignment {
	ratio := o.activeRatio
	if ratio < 0 {
		switch o.scenario {
		case "mostly-viewing":
			ratio = .05
		case "viewports":
			ratio = .70
		case "hotspot":
			ratio = 1
		default:
			ratio = .20
		}
	}
	active := o.activeDrawers
	if active < 0 {
		active = int(float64(o.connections) * ratio)
		if ratio > 0 && active == 0 {
			active = 1
		}
	}
	a := make([]assignment, o.connections)
	for i := range a {
		note, page := i%o.canvases, i%o.pages
		x, y := 512.0, 384.0
		switch o.scenario {
		case "distributed":
			x, y = float64((i%10)*160), float64((i%6)*130)
		case "viewports":
			note = 0
			x, y = float64((i%4)*480), float64((i%3)*320)
		case "hotspot":
			note, page, x, y = 0, 0, 512, 384
		case "mostly-viewing", "multi-page":
			note = 0
		}
		if o.scenario == "mostly-viewing" {
			page = 0
		}
		a[i] = assignment{userID: fmt.Sprintf("bench-user-%06d", i), noteID: fmt.Sprintf("bench-note-%03d", note), pageID: fmt.Sprintf("bench-page-%03d", page), x: x, y: y, active: i < active}
	}
	return a
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("private key must be ES256 P-256")
	}
	return key, nil
}

func signToken(key *ecdsa.PrivateKey, o options, a assignment) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{"iss": o.issuer, "aud": o.audience, "sub": a.userID, "nid": a.noteID, "sid": "bench-session-" + a.userID, "jti": "bench-token-" + a.userID, "perm": "edit", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(30 * time.Minute).Unix()}
	return jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
}

func bootstrap(ctx context.Context, o options, token string) (bootstrapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.baseURL, "/")+"/v1/sessions/bootstrap", nil)
	if err != nil {
		return bootstrapResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", o.origin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return bootstrapResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return bootstrapResponse{}, fmt.Errorf("bootstrap returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var result bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, err
	}
	if result.ConnectionTicket == "" || result.SessionID == "" {
		return result, errors.New("bootstrap response has no session/ticket")
	}
	return result, nil
}

func openVirtualUser(ctx context.Context, o options, a assignment, key *ecdsa.PrivateKey) (*virtualUser, error) {
	token, err := signToken(key, o, a)
	if err != nil {
		return nil, err
	}
	b, err := bootstrap(ctx, o, token)
	if err != nil {
		return nil, err
	}
	if b.NoteID != "" {
		a.noteID = b.NoteID
	}
	var conn loadConnection
	var cleanup func()
	if o.transport == "websocket" {
		conn, err = dialWebSocket(ctx, o, b)
	} else {
		conn, cleanup, err = dialWebTransport(ctx, o, b)
	}
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	u := &virtualUser{assignment: a, bootstrap: b, conn: conn, cleanup: cleanup}
	if b.BinaryVersion >= 2 {
		if _, err = u.sendRaw(ctx, "protocol.capabilities", map[string]any{"binaryAggregateVersion": 1}, false, false, nil); err != nil {
			_ = u.close()
			return nil, err
		}
	}
	if _, err = u.sendRaw(ctx, "interest.update", map[string]any{"pageId": a.pageID, "x": a.x - 600, "y": a.y - 450, "width": 1200, "height": 900, "zoom": 1}, false, false, nil); err != nil {
		_ = u.close()
		return nil, err
	}
	return u, nil
}

func dialWebSocket(ctx context.Context, o options, b bootstrapResponse) (loadConnection, error) {
	connect := withTicket(b.WebSocketURL, b.ConnectionTicket)
	if connect == "" {
		connect = withTicket(deriveWSURL(o.baseURL), b.ConnectionTicket)
	}
	conn, _, err := websocket.Dial(ctx, connect, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{o.origin}}})
	if err != nil {
		return nil, err
	}
	return &wsConnection{conn: conn}, nil
}

func dialWebTransport(ctx context.Context, o options, b bootstrapResponse) (loadConnection, func(), error) {
	if b.WebTransportURL == "" {
		return nil, nil, errors.New("bootstrap did not advertise webTransportUrl")
	}
	transport := &webtransport.Transport{ApplicationProtocols: []string{"canvas-realtime"}, TLSClientConfig: &tls.Config{InsecureSkipVerify: o.insecureTLS}, QUICConfig: &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true}}
	resp, session, err := transport.Dial(ctx, withTicket(b.WebTransportURL, b.ConnectionTicket), http.Header{"Origin": []string{o.origin}})
	if err != nil {
		_ = transport.Close()
		return nil, nil, fmt.Errorf("webtransport dial: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = transport.Close()
		return nil, nil, fmt.Errorf("webtransport returned %s", resp.Status)
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		_ = session.CloseWithError(0, "no control stream")
		_ = transport.Close()
		return nil, nil, err
	}
	return newWTConnection(session, stream), func() { _ = transport.Close() }, nil
}

func deriveWSURL(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/ws"
	u.RawQuery = ""
	return u.String()
}

func withTicket(raw, ticket string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()
	return u.String()
}

func (u *virtualUser) nextSeq() uint64 { return u.seq.Add(1) }

func (u *virtualUser) sendRaw(ctx context.Context, event string, payload any, ephemeral, binaryFrame bool, seq *uint64) (int, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	envelope := &domain.Envelope{V: domain.EnvelopeVersion, MessageID: fmt.Sprintf("%s-%d", u.assignment.userID, time.Now().UnixNano()), Event: event, Seq: seq, SentAt: time.Now().UnixMilli(), Payload: rawPayload}
	wireData, err := json.Marshal(envelope)
	if err != nil {
		return 0, err
	}
	if binaryFrame {
		data, ok := codec.EncodeClientFrame(envelope)
		if !ok {
			return 0, fmt.Errorf("cannot encode %s as binary", event)
		}
		wireData = data
	}
	return u.conn.write(ctx, wireData, ephemeral, binaryFrame)
}

func (u *virtualUser) sendPreview(ctx context.Context, state *runState, event string, payload any) error {
	seq := u.nextSeq()
	now := time.Now()
	state.recordSend(u.assignment.userID, seq, now)
	binaryFrame := state.opts.encoding == "binary" && u.bootstrap.BinaryVersion >= 1
	written, err := u.sendRaw(ctx, event, payload, true, binaryFrame, &seq)
	if err == nil {
		state.sendMessages.Add(1)
		state.sendBytes.Add(int64(written))
	}
	return err
}

func (u *virtualUser) sendCommit(ctx context.Context, state *runState, index int) error {
	if state.opts.commitEvery <= 0 {
		return nil
	}
	id := fmt.Sprintf("%s-stroke-%d-%d", u.assignment.userID, index, time.Now().UnixNano())
	payload := map[string]any{"clientStrokeId": id, "operationId": "bench-op-" + id, "pageId": u.assignment.pageID, "drawingBlockId": "bench-drawing-block", "points": []map[string]float64{{"x": u.assignment.x, "y": u.assignment.y}, {"x": u.assignment.x + 16, "y": u.assignment.y + 12}}}
	written, err := u.sendRaw(ctx, "ink.commit", payload, false, false, nil)
	if err != nil {
		return err
	}
	state.sendMessages.Add(1)
	state.sendBytes.Add(int64(written))
	state.commitSent.Add(1)
	state.expectedCommitDeliveries.Add(int64(state.sameNotePeers(u.assignment.noteID)))
	return nil
}

func (u *virtualUser) run(ctx context.Context, state *runState, start time.Time) {
	readDone := make(chan struct{})
	go func() { defer close(readDone); u.readLoop(ctx, state) }()
	if !u.assignment.active || state.opts.previewRate <= 0 {
		select {
		case <-ctx.Done():
		case <-state.stopSending:
		}
		return
	}
	interval := time.Duration(float64(time.Second) / state.opts.previewRate)
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var commits *time.Ticker
	var commitC <-chan time.Time
	if state.opts.commitEvery > 0 {
		commits = time.NewTicker(state.opts.commitEvery)
		commitC = commits.C
		defer commits.Stop()
	}
	index := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-state.stopSending:
			return
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			d := 18 * elapsed
			if err := u.sendPreview(ctx, state, "cursor.moved", map[string]any{"pageId": u.assignment.pageID, "x": u.assignment.x + d, "y": u.assignment.y + d/2}); err != nil {
				return
			}
		case <-commitC:
			_ = u.sendCommit(ctx, state, index)
			index++
		}
	}
}

func (u *virtualUser) readLoop(ctx context.Context, state *runState) {
	for {
		frame, err := u.conn.read(ctx)
		if err != nil {
			return
		}
		state.receiveMessages.Add(1)
		state.receiveBytes.Add(int64(len(frame.data)))
		if frame.binary {
			metadata, err := codec.DecodeRelayMetadata(frame.data)
			if err != nil {
				state.unexpectedMessages.Add(1)
				continue
			}
			for _, item := range metadata {
				state.observePreview(u.assignment.userID, item.ActorID, item.Sequence, time.Now())
			}
			continue
		}
		var envelope struct {
			Event   string  `json:"event"`
			ActorID string  `json:"actorId"`
			Seq     *uint64 `json:"seq"`
		}
		if json.Unmarshal(frame.data, &envelope) != nil {
			state.unexpectedMessages.Add(1)
			continue
		}
		if envelope.Event == "ink.commit" {
			state.commitReceived.Add(1)
		}
		if envelope.Seq != nil {
			state.observePreview(u.assignment.userID, envelope.ActorID, *envelope.Seq, time.Now())
		}
	}
}

func (u *virtualUser) close() error {
	if u.cleanup != nil {
		defer u.cleanup()
	}
	return u.conn.close()
}

func (s *runState) recordSend(user string, seq uint64, at time.Time) {
	s.sentMu.Lock()
	defer s.sentMu.Unlock()
	bySeq := s.sentAt[user]
	if bySeq == nil {
		bySeq = make(map[uint64]time.Time)
		s.sentAt[user] = bySeq
	}
	bySeq[seq] = at
	s.previewSent.Add(1)
}

func (s *runState) observePreview(receiver, actor string, seq uint64, at time.Time) {
	if actor == "" || seq == 0 || actor == receiver {
		return
	}
	s.sentMu.RLock()
	sent, ok := s.sentAt[actor][seq]
	s.sentMu.RUnlock()
	if !ok {
		return
	}
	s.previewReceived.Add(1)
	s.latMu.Lock()
	if len(s.latencies) < 200_000 {
		s.latencies = append(s.latencies, float64(at.Sub(sent).Microseconds())/1000)
	}
	s.latMu.Unlock()
}

func (s *runState) sameNotePeers(note string) int {
	n := 0
	for _, a := range s.assignments {
		if a.noteID == note {
			n++
		}
	}
	if n > 0 {
		return n - 1
	}
	return 0
}

func fetchMetrics(base string) (metricsSnapshot, string) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/metrics", nil)
	if err != nil {
		return metricsSnapshot{}, err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return metricsSnapshot{}, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return metricsSnapshot{}, resp.Status
	}
	var snapshot metricsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return snapshot, err.Error()
	}
	return snapshot, ""
}

func makeReport(s *runState, start, end time.Time) report {
	seconds := end.Sub(start).Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	s.latMu.Lock()
	samples := append([]float64(nil), s.latencies...)
	s.latMu.Unlock()
	sort.Float64s(samples)
	o := observedReport{ConnectionsAttempted: s.attempted.Load(), ConnectionsOpened: s.opened.Load(), ConnectionFailures: s.failures.Load(), ConnectionsClosed: s.closed.Load(), Reconnects: s.reconnects.Load(), LocalSendMessages: s.sendMessages.Load(), LocalReceiveMessages: s.receiveMessages.Load(), LocalSendBytes: s.sendBytes.Load(), LocalReceiveBytes: s.receiveBytes.Load(), PreviewSent: s.previewSent.Load(), PreviewReceived: s.previewReceived.Load(), CommitsSent: s.commitSent.Load(), CommitsReceived: s.commitReceived.Load(), ExpectedCommitDeliveries: s.expectedCommitDeliveries.Load(), UnexpectedMessages: s.unexpectedMessages.Load(), P50PreviewLatencyMs: percentile(samples, .50), P95PreviewLatencyMs: percentile(samples, .95), P99PreviewLatencyMs: percentile(samples, .99), MessagesPerSecond: float64(s.sendMessages.Load()+s.receiveMessages.Load()) / seconds, IncomingBytesPerSecond: float64(s.receiveBytes.Load()) / seconds, OutgoingBytesPerSecond: float64(s.sendBytes.Load()) / seconds, BytesPerUser: float64(s.sendBytes.Load()+s.receiveBytes.Load()) / float64(max64(1, s.opened.Load())) / seconds}
	if o.ExpectedCommitDeliveries > 0 {
		o.FinalCommitDeliveryRate = float64(o.CommitsReceived) / float64(o.ExpectedCommitDeliveries)
	}
	deltaIn := s.serverAfter.MessagesIn - s.serverBefore.MessagesIn
	deltaOut := s.serverAfter.MessagesOut - s.serverBefore.MessagesOut
	server := serverReport{MetricsBefore: s.serverBefore, MetricsAfter: s.serverAfter, MessagesPerSecond: float64(deltaIn+deltaOut) / seconds, IncomingBytesPerSecond: float64(s.serverAfter.IncomingBytes-s.serverBefore.IncomingBytes) / seconds, OutgoingBytesPerSecond: float64(s.serverAfter.OutgoingBytes-s.serverBefore.OutgoingBytes) / seconds, RecipientsPerEvent: s.serverAfter.InterestRecipientsPerEvent, DroppedEphemeral: s.serverAfter.DroppedEphemeral - s.serverBefore.DroppedEphemeral, ReliableOverflow: s.serverAfter.ReliableOverflow - s.serverBefore.ReliableOverflow, InterestFiltered: s.serverAfter.InterestFiltered - s.serverBefore.InterestFiltered, QueueDepthMax: max64(s.serverAfter.ReliableQueueDepthMax, s.serverAfter.EphemeralQueueDepthMax), MetricsError: s.serverError}
	notes := []string{"CPU/RAM are not inferred from load-generator counters; use scripts/run-load-test.ps1 or an OS monitor and attach samples.", "Commit correctness measures reliable Go relay delivery to expected connected peers, not .NET/PostgreSQL canonical persistence.", "WebRTC is intentionally not measured by this Go runner; use a real browser ICE/DataChannel run and keep its result separate."}
	return report{GeneratedAt: end.UTC().Format(time.RFC3339), GoVersion: runtime.Version(), Run: runReport{BaseURL: s.opts.baseURL, Transport: s.opts.transport, Encoding: s.opts.encoding, Scenario: s.opts.scenario, Connections: s.opts.connections, Duration: s.opts.duration.String(), PreviewRate: s.opts.previewRate, ActiveRatio: s.opts.activeRatio, ActiveDrawers: s.opts.activeDrawers, Canvases: s.opts.canvases, Pages: s.opts.pages}, Observed: o, Server: server, Notes: notes}
}

func percentile(values []float64, fraction float64) float64 {
	if len(values) == 0 {
		return 0
	}
	return values[int(float64(len(values)-1)*fraction+.5)]
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func writeReport(path string, r report) error {
	jsonPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".json"
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(renderMarkdown(r)), 0o644)
}

func renderMarkdown(r report) string {
	o, s := r.Observed, r.Server
	return fmt.Sprintf(`# Canvas realtime load-test report

Generated: %s  
Go: %s

## Run

| Field | Value |
|---|---:|
| Transport | %s |
| Encoding | %s |
| Scenario | %s |
| Connections requested/opened | %d / %d |
| Duration | %s |
| Preview rate | %.2f/s per active drawer |

## Results

| Metric | Value |
|---|---:|
| Preview latency p50 | %.2f ms |
| Preview latency p95 | %.2f ms |
| Preview latency p99 | %.2f ms |
| Messages/sec | %.2f |
| Incoming bandwidth | %.2f B/s |
| Outgoing bandwidth | %.2f B/s |
| Bandwidth/user | %.2f B/s |
| Preview sent / received | %d / %d |
| Commits sent / received | %d / %d |
| Expected commit deliveries | %d |
| Reliable commit delivery rate | %.2f%% |
| Connection failures | %d |
| Reconnects | %d |

## Go server observations

| Metric | Value |
|---|---:|
| Server messages/sec | %.2f |
| Server incoming bandwidth | %.2f B/s |
| Server outgoing bandwidth | %.2f B/s |
| Recipients/event | %.2f |
| Interest-filtered frames | %d |
| Dropped ephemeral frames | %d |
| Reliable overflows | %d |
| Max queue depth | %d |

CPU/RAM are intentionally not fabricated by this runner. Capture them with scripts/run-load-test.ps1 or an OS profiler.

## Interpretation

This is one Go instance with in-memory stores. It describes this exact machine, build, network and scenario; it is not a universal capacity guarantee. It does **not** claim support for 500 simultaneous same-viewport drawers. Publish a capacity only after running 100/500/1000 users across all required scenarios and reviewing browser FPS/main-thread time as well as server results.

WebRTC small-room results are excluded because a signaling path is not a browser ICE/DataChannel benchmark. WebTransport and Go WebSocket are comparable when the WT listener is TLS-enabled and the same scenario/settings are used.

Raw counters are in the sibling JSON file.

`, r.GeneratedAt, r.GoVersion, r.Run.Transport, r.Run.Encoding, r.Run.Scenario, r.Run.Connections, o.ConnectionsOpened, r.Run.Duration, r.Run.PreviewRate, o.P50PreviewLatencyMs, o.P95PreviewLatencyMs, o.P99PreviewLatencyMs, o.MessagesPerSecond, o.IncomingBytesPerSecond, o.OutgoingBytesPerSecond, o.BytesPerUser, o.PreviewSent, o.PreviewReceived, o.CommitsSent, o.CommitsReceived, o.ExpectedCommitDeliveries, o.FinalCommitDeliveryRate*100, o.ConnectionFailures, o.Reconnects, s.MessagesPerSecond, s.IncomingBytesPerSecond, s.OutgoingBytesPerSecond, s.RecipientsPerEvent, s.InterestFiltered, s.DroppedEphemeral, s.ReliableOverflow, s.QueueDepthMax)
}

func printSummary(r report) {
	o := r.Observed
	fmt.Printf("scenario=%s transport=%s encoding=%s opened=%d/%d p50=%.2fms p95=%.2fms p99=%.2fms commits=%d/%d\n", r.Run.Scenario, r.Run.Transport, r.Run.Encoding, o.ConnectionsOpened, r.Run.Connections, o.P50PreviewLatencyMs, o.P95PreviewLatencyMs, o.P99PreviewLatencyMs, o.CommitsReceived, o.ExpectedCommitDeliveries)
}
