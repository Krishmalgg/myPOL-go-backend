package transport

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"mypol/go-realtime/internal/testsupport"
)

// Plan P4.3: a quiet client keeps its connection with a heartbeat, and any
// traffic keeps its session, so an in-socket token refresh still finds it.

func TestAHeartbeatKeepsAQuietSocketOpenAndIsAnsweredOnlyToItsSender(t *testing.T) {
	h := newWSHarnessWithIdle(t, 300*time.Millisecond)
	quiet := h.connect(t, testsupport.ClaimsInput{SessionID: "quiet", UserID: "u-quiet"})
	readEnvelope(t, quiet)
	peer := h.connect(t, testsupport.ClaimsInput{SessionID: "peer", UserID: "u-peer"})
	readEnvelope(t, peer)
	readEnvelope(t, quiet) // presence of the peer

	for i := 0; i < 10; i++ { // 1 s, over three idle timeouts
		send(t, quiet, EventHeartbeat, `{}`)
		if envelope := readEnvelope(t, quiet); envelope.Event != EventHeartbeatAck {
			t.Fatalf("reply = %q, want %q", envelope.Event, EventHeartbeatAck)
		}
		send(t, peer, EventHeartbeat, `{}`)
		if envelope := readEnvelope(t, peer); envelope.Event != EventHeartbeatAck {
			t.Fatalf("the peer saw %q: heartbeats must not be relayed", envelope.Event)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := h.metrics.Snapshot().ConnectionsClosedByReason[CloseReasonIdle]; got != 0 {
		t.Fatalf("idle closes = %d, want 0 while heartbeating", got)
	}
}

func TestTrafficKeepsTheSessionSoARefreshFindsIt(t *testing.T) {
	h := newWSHarness(t)
	in := testsupport.ClaimsInput{SessionID: "busy", UserID: "u", NoteID: "n"}
	socket := h.connect(t, in)
	readEnvelope(t, socket)

	for i := 0; i < 7; i++ { // 1.2 s of cursor traffic; touches are at most 1/s
		send(t, socket, "cursor.moved", `{"x":1,"y":1}`)
		time.Sleep(200 * time.Millisecond)
	}
	// Stands in for the 45 s idle sweep: the session was touched within the last second.
	if swept := h.sessions.SweepSessions(1100 * time.Millisecond); swept != 0 {
		t.Fatalf("swept %d sessions with a busy socket", swept)
	}
	token, err := h.keys.Sign(testsupport.Claims(in))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	send(t, socket, EventAuthRefresh, fmt.Sprintf(`{"token":%q}`, token))
	if envelope := readEnvelope(t, socket); envelope.Event != EventAuthRefreshed {
		t.Fatalf("refresh = %q, want %q", envelope.Event, EventAuthRefreshed)
	}
}

func TestWebTransportCountsStreamTrafficAsActivityAndReapsSilence(t *testing.T) {
	h := newWTHarnessWithIdle(t, 300*time.Millisecond)
	_, stream := h.dial(t, h.ticket(t, testsupport.ClaimsInput{}))
	readFrame(t, stream) // roster

	// Reliable-only traffic: before P4.3 only datagrams reset the idle deadline.
	for i := 0; i < 10; i++ {
		writeFrame(t, stream, `{"v":2,"event":"heartbeat","payload":{}}`)
		if envelope := readFrame(t, stream); envelope.Event != EventHeartbeatAck {
			t.Fatalf("reply = %q, want %q", envelope.Event, EventHeartbeatAck)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Then silence: the watchdog closes the session.
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(stream)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("a silent WebTransport session was not reaped")
	}
}
