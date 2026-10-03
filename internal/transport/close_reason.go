package transport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/observability"
)

// Why a connection ended (plan P4.1). Reconnect churn cannot be diagnosed
// from "read ended": an idle reap, a client that navigated away and a broken
// network all looked the same in the log.
const (
	CloseReasonIdle        = "idle timeout"
	CloseReasonReadFailed  = "read failed"
	CloseReasonClient      = "client closed"
	CloseReasonStreamEnded = "control stream ended"
)

// wsReadEndReason names why a WebSocket read ended. A client close keeps its
// code, e.g. "client closed (1001)".
func wsReadEndReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return CloseReasonIdle
	}
	if code := websocket.CloseStatus(err); code != -1 {
		return fmt.Sprintf("%s (%d)", CloseReasonClient, code)
	}
	return CloseReasonReadFailed
}

// wtReadEndReason does the same for a WebTransport session; fallback names the
// reader that ended when the cause is neither an idle reap nor the client.
func wtReadEndReason(err error, fallback string) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return CloseReasonIdle
	}
	var sessionErr *webtransport.SessionError
	if errors.As(err, &sessionErr) && sessionErr.Remote {
		return fmt.Sprintf("%s (%d)", CloseReasonClient, sessionErr.ErrorCode)
	}
	return fallback
}

// closedConnection is what the disconnect log needs from either transport.
type closedConnection interface {
	ID() string
	SessionID() string
	CloseReason() string
}

// recordClose counts the reason and returns the log fields shared by both
// transports, so the two disconnect lines can be compared directly.
func recordClose(metrics *observability.Metrics, connection closedConnection, transport string, openedAt, now time.Time) []any {
	reason := connection.CloseReason()
	if metrics != nil {
		metrics.ObserveClose(reason)
	}
	return []any{
		"connectionId", connection.ID(),
		"sessionId", connection.SessionID(),
		"transport", transport,
		"reason", reason,
		"openSeconds", int(now.Sub(openedAt).Seconds()),
	}
}
