package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/observability"
	"mypol/go-realtime/internal/testsupport"
)

// Plan P4.1: every disconnect is counted by why it happened, so reconnect
// churn can be measured instead of guessed.

func waitForClose(t *testing.T, metrics *observability.Metrics, reason string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if metrics.Snapshot().ConnectionsClosedByReason[reason] > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no close counted as %q; got %v", reason, metrics.Snapshot().ConnectionsClosedByReason)
}

func TestASilentClientIsClosedAsIdleEvenWhileItReceives(t *testing.T) {
	h := newWSHarnessWithIdle(t, 300*time.Millisecond)
	watcher := h.connect(t, testsupport.ClaimsInput{SessionID: "watcher", UserID: "u-watch"})
	readEnvelope(t, watcher)
	drawer := h.connect(t, testsupport.ClaimsInput{SessionID: "drawer", UserID: "u-draw"})
	readEnvelope(t, drawer)

	// The drawer keeps sending; the watcher only receives. Receiving does not
	// count as activity, so the watcher is reaped.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				frame, _ := json.Marshal(map[string]any{"v": 2, "event": "cursor.moved", "payload": map[string]any{"x": 1, "y": 2}})
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_ = drawer.Write(ctx, websocket.MessageText, frame)
				cancel()
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		if _, _, err := watcher.Read(ctx); err != nil {
			break
		}
	}
	waitForClose(t, h.metrics, CloseReasonIdle)
	if got := h.metrics.Snapshot().ConnectionsClosedByReason[CloseReasonIdle]; got != 1 {
		t.Fatalf("idle closes = %d, want 1 (only the silent watcher)", got)
	}
}

func TestAClientCloseIsCountedWithoutItsCode(t *testing.T) {
	h := newWSHarness(t)
	socket := h.connect(t, testsupport.ClaimsInput{SessionID: "leaving"})
	readEnvelope(t, socket)

	_ = socket.Close(websocket.StatusGoingAway, "page hidden")
	waitForClose(t, h.metrics, CloseReasonClient)
}

func TestAuthRefreshOutcomesAreCounted(t *testing.T) {
	h := newWSHarness(t)
	in := testsupport.ClaimsInput{SessionID: "refreshing", UserID: "u-1", NoteID: "note-1"}
	socket := h.connect(t, in)
	readEnvelope(t, socket)

	token, err := h.keys.Sign(testsupport.Claims(in))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	send(t, socket, EventAuthRefresh, fmt.Sprintf(`{"token":%q}`, token))
	if envelope := readEnvelope(t, socket); envelope.Event != EventAuthRefreshed {
		t.Fatalf("event = %q, want %q", envelope.Event, EventAuthRefreshed)
	}
	send(t, socket, EventAuthRefresh, `{"token":"not-a-token"}`)
	if envelope := readEnvelope(t, socket); envelope.Event != EventAuthRejected {
		t.Fatalf("event = %q, want %q", envelope.Event, EventAuthRejected)
	}

	snapshot := h.metrics.Snapshot()
	if snapshot.AuthRefreshAccepted != 1 || snapshot.AuthRefreshRejected != 1 {
		t.Fatalf("accepted/rejected = %d/%d, want 1/1", snapshot.AuthRefreshAccepted, snapshot.AuthRefreshRejected)
	}
}

func TestReadEndReasons(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ws idle", wsReadEndReason(fmt.Errorf("read: %w", context.DeadlineExceeded)), CloseReasonIdle},
		{"ws client", wsReadEndReason(websocket.CloseError{Code: websocket.StatusGoingAway}), "client closed (1001)"},
		{"ws network", wsReadEndReason(errors.New("connection reset")), CloseReasonReadFailed},
		{"wt idle", wtReadEndReason(context.DeadlineExceeded, "datagram read ended"), CloseReasonIdle},
		{"wt client", wtReadEndReason(&webtransport.SessionError{Remote: true, ErrorCode: 0}, "x"), "client closed (0)"},
		{"wt local", wtReadEndReason(&webtransport.SessionError{Remote: false}, "datagram read ended"), "datagram read ended"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestCloseCountsDropTheDetailAndStayBounded(t *testing.T) {
	metrics := observability.New()
	metrics.ObserveClose("client closed (1001)")
	metrics.ObserveClose("client closed (1000)")
	metrics.ObserveClose("")
	for i := 0; i < 40; i++ {
		metrics.ObserveClose(fmt.Sprintf("reason-%d", i))
	}
	counts := metrics.Snapshot().ConnectionsClosedByReason
	if counts["client closed"] != 2 || counts["unknown"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if len(counts) > 33 || counts["other"] == 0 {
		t.Fatalf("%d reasons, other = %d: the map must stay bounded", len(counts), counts["other"])
	}
}
