package transport

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/coder/websocket"

	"mypol/go-realtime/internal/codec"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
)

// Eight milliseconds keeps server-side coalescing below one 60Hz display
// frame. Browser batching still collapses duplicate state, while recipients no
// longer pay two full frame windows before a preview can be painted.
const ephemeralFlushInterval = 8 * time.Millisecond
const maxEphemeralAggregateFrames = 64

// wsConnection is one authenticated WebSocket attached to a canvas room.
//
// Sends never touch the socket directly. Everything is queued and drained by a
// single writer goroutine, because a WebSocket permits only one concurrent
// writer — and because the queues are what give ephemeral and reliable traffic
// their different failure behaviour.
type wsConnection struct {
	*outboundQueues

	id        string
	sessionID string
	userID    string
	noteID    string

	mu              sync.RWMutex
	permission      domain.Permission
	binaryFrames    bool
	aggregateFrames bool

	socket      *websocket.Conn
	metrics     *observability.Metrics
	connectedAt time.Time
}

func newWSConnection(
	id string,
	ticket *domain.ConnectionTicket,
	socket *websocket.Conn,
	ephemeralQueueSize, reliableQueueSize int,
	metrics *observability.Metrics,
	now time.Time,
) *wsConnection {
	return &wsConnection{
		outboundQueues: newOutboundQueues(ephemeralQueueSize, reliableQueueSize),
		id:             id,
		sessionID:      ticket.SessionID,
		userID:         ticket.UserID,
		noteID:         ticket.NoteID,
		permission:     ticket.Permission,
		socket:         socket,
		metrics:        metrics,
		connectedAt:    now,
	}
}

func (c *wsConnection) ID() string             { return c.id }
func (c *wsConnection) SessionID() string      { return c.sessionID }
func (c *wsConnection) UserID() string         { return c.userID }
func (c *wsConnection) NoteID() string         { return c.noteID }
func (c *wsConnection) ConnectedAt() time.Time { return c.connectedAt }

func (c *wsConnection) Permission() domain.Permission {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.permission
}

func (c *wsConnection) SetPermission(permission domain.Permission) {
	c.mu.Lock()
	c.permission = permission
	c.mu.Unlock()
}

// EnableBinaryFrames is called only after this socket supplied a valid binary
// preview. It is an opportunistic, backward-compatible capability negotiation:
// a still-open older browser keeps receiving JSON and remains fully usable.
func (c *wsConnection) EnableBinaryFrames() {
	c.mu.Lock()
	c.binaryFrames = true
	c.mu.Unlock()
}

// EnableBinaryAggregates is an explicit client capability. It is separate from
// ordinary binary support so a Phase-16 browser never receives an unknown
// aggregate frame during a rolling deployment.
func (c *wsConnection) EnableBinaryAggregates() {
	c.mu.Lock()
	c.aggregateFrames = true
	c.mu.Unlock()
}

func (c *wsConnection) supportsBinaryFrames() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryFrames
}

func (c *wsConnection) supportsBinaryAggregates() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryFrames && c.aggregateFrames
}

func (c *wsConnection) SendReliable(envelope *domain.Envelope) error {
	err := c.pushReliable(envelope)
	if err != nil && c.metrics != nil {
		c.metrics.ReliableOverflow.Add(1)
	}
	if c.metrics != nil {
		c.metrics.ObserveQueueDepth(c.PendingReliable(), c.PendingEphemeral())
	}
	return err
}

func (c *wsConnection) SendEphemeral(envelope *domain.Envelope, coalesceKey string) {
	droppedBefore := c.Dropped()
	c.pushEphemeral(envelope, coalesceKey)
	if c.metrics != nil {
		c.metrics.DroppedEphemeral.Add(int64(c.Dropped() - droppedBefore))
		c.metrics.ObserveQueueDepth(c.PendingReliable(), c.PendingEphemeral())
	}
}

func (c *wsConnection) PendingReliable() int { return c.outboundQueues.PendingReliable() }

func (c *wsConnection) Close(reason string) {
	alreadyClosed := c.isClosed()
	c.markClosed()
	if alreadyClosed {
		return
	}
	// StatusNormalClosure: the peer should reconnect, not treat this as a
	// protocol failure.
	_ = c.socket.Close(websocket.StatusNormalClosure, truncateReason(reason))
}

// writePump is the only goroutine that writes to the socket.
func (c *wsConnection) writePump(ctx context.Context, writeTimeout time.Duration) {
	ticker := time.NewTicker(ephemeralFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-c.wake:
			if !c.drainReliable(ctx, writeTimeout) {
				return
			}
		case <-ticker.C:
			if !c.drainEphemeral(ctx, writeTimeout) {
				return
			}
		}
	}
}

// drain empties both queues, reliable first: a commit must not wait behind a
// queue of cursor frames, which are individually worthless by comparison.
func (c *wsConnection) drainReliable(ctx context.Context, writeTimeout time.Duration) bool {
	for {
		if envelope := c.takeReliable(); envelope != nil {
			c.beginReliableWrite()
			written := c.write(ctx, envelope, writeTimeout)
			c.endReliableWrite()
			if !written {
				return false
			}
			continue
		}

		return true
	}
}

func (c *wsConnection) drainEphemeral(ctx context.Context, writeTimeout time.Duration) bool {
	for {
		batch := c.takeEphemeralBatch(maxEphemeralAggregateFrames)
		if len(batch) == 0 {
			return true
		}
		if len(batch) > 1 && c.supportsBinaryAggregates() {
			if encoded, ok := codec.EncodeRelayAggregate(batch); ok {
				if !c.writeRaw(ctx, websocket.MessageBinary, encoded, writeTimeout) {
					return false
				}
				continue
			}
		}
		for _, envelope := range batch {
			if !c.write(ctx, envelope, writeTimeout) {
				return false
			}
		}
	}
}

func (c *wsConnection) write(ctx context.Context, envelope *domain.Envelope, timeout time.Duration) bool {
	encoded, messageType := c.wireBytes(envelope)
	if encoded == nil {
		// A message we cannot encode is a bug, not a transport failure; drop it
		// rather than tearing down a healthy connection.
		return true
	}

	return c.writeRaw(ctx, messageType, encoded, timeout)
}

func (c *wsConnection) writeRaw(ctx context.Context, messageType websocket.MessageType, encoded []byte, timeout time.Duration) bool {
	writeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := c.socket.Write(writeCtx, messageType, encoded); err != nil {
		c.Close("write failed")
		return false
	}
	if c.metrics != nil {
		c.metrics.MessagesOut.Add(1)
		c.metrics.OutgoingBytes.Add(int64(len(encoded)))
	}
	return true
}

// wireBytes keeps Phase 16's scope tight: only ephemeral events go binary.
// Reliable/control messages always stay JSON even on a binary-capable socket.
func (c *wsConnection) wireBytes(envelope *domain.Envelope) ([]byte, websocket.MessageType) {
	if c.supportsBinaryFrames() && domain.ClassifyEvent(envelope.Event) == domain.ClassEphemeral {
		if encoded, ok := codec.EncodeRelayFrame(envelope); ok {
			return encoded, websocket.MessageBinary
		}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, websocket.MessageText
	}
	return encoded, websocket.MessageText
}

func truncateReason(reason string) string {
	// Close frames cap the reason at 123 bytes.
	if len(reason) > 120 {
		return reason[:120]
	}
	return reason
}
