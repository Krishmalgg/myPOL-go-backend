package transport

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"

	"mypol/go-realtime/internal/domain"
)

var errReliableQueueFull = errors.New("reliable queue full")

// wsConnection is one authenticated WebSocket attached to a canvas room.
//
// Sends never touch the socket directly. Everything is queued and drained by a
// single writer goroutine, because a WebSocket permits only one concurrent
// writer and because it is the queues — not the socket — that let ephemeral and
// reliable traffic have different failure behaviour.
type wsConnection struct {
	id        string
	sessionID string
	userID    string
	noteID    string

	mu         sync.RWMutex
	permission domain.Permission

	socket *websocket.Conn

	// ephemeral is newest-wins per coalesce key. A slow reader loses stale
	// frames rather than accumulating every frame produced while it was slow.
	ephemeralMu    sync.Mutex
	ephemeral      map[string]*domain.Envelope
	ephemeralOrder []string
	maxEphemeral   int
	dropped        uint64

	// reliable is a bounded FIFO that refuses rather than discards.
	reliable chan *domain.Envelope

	// wake signals the writer that work is queued, without blocking the sender.
	wake chan struct{}

	connectedAt time.Time
	closeOnce   sync.Once
	closed      chan struct{}
	closeReason string
}

func newWSConnection(
	id string,
	ticket *domain.ConnectionTicket,
	socket *websocket.Conn,
	ephemeralQueueSize, reliableQueueSize int,
	now time.Time,
) *wsConnection {
	return &wsConnection{
		id:           id,
		sessionID:    ticket.SessionID,
		userID:       ticket.UserID,
		noteID:       ticket.NoteID,
		permission:   ticket.Permission,
		socket:       socket,
		ephemeral:    make(map[string]*domain.Envelope, ephemeralQueueSize),
		maxEphemeral: ephemeralQueueSize,
		reliable:     make(chan *domain.Envelope, reliableQueueSize),
		wake:         make(chan struct{}, 1),
		connectedAt:  now,
		closed:       make(chan struct{}),
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

// SendReliable queues a message that must arrive, refusing when full.
//
// Returning an error rather than blocking is deliberate: blocking here would
// stall whichever goroutine is fanning out to the whole room, letting one slow
// client freeze everyone else.
func (c *wsConnection) SendReliable(envelope *domain.Envelope) error {
	select {
	case <-c.closed:
		return nil
	default:
	}

	select {
	case c.reliable <- envelope:
		c.signal()
		return nil
	default:
		return errReliableQueueFull
	}
}

// SendEphemeral queues a droppable frame, replacing any queued frame with the
// same key.
func (c *wsConnection) SendEphemeral(envelope *domain.Envelope, coalesceKey string) {
	select {
	case <-c.closed:
		return
	default:
	}

	c.ephemeralMu.Lock()
	if _, exists := c.ephemeral[coalesceKey]; exists {
		c.dropped++
	} else {
		c.ephemeralOrder = append(c.ephemeralOrder, coalesceKey)
	}
	c.ephemeral[coalesceKey] = envelope

	// Under sustained pressure shed the oldest stream: an ancient cursor
	// position is worth less than a current one.
	for len(c.ephemeralOrder) > c.maxEphemeral {
		oldest := c.ephemeralOrder[0]
		c.ephemeralOrder = c.ephemeralOrder[1:]
		delete(c.ephemeral, oldest)
		c.dropped++
	}
	c.ephemeralMu.Unlock()

	c.signal()
}

func (c *wsConnection) Close(reason string) {
	c.closeOnce.Do(func() {
		c.closeReason = reason
		close(c.closed)
		// StatusNormalClosure: the peer should reconnect, not treat this as a
		// protocol failure.
		_ = c.socket.Close(websocket.StatusNormalClosure, truncateReason(reason))
	})
}

func (c *wsConnection) Dropped() uint64 {
	c.ephemeralMu.Lock()
	defer c.ephemeralMu.Unlock()
	return c.dropped
}

// signal nudges the writer without ever blocking the sender.
func (c *wsConnection) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// writePump is the only goroutine that writes to the socket.
//
// Reliable messages drain first: a commit must not wait behind a queue of
// cursor frames, which are individually worthless by comparison.
func (c *wsConnection) writePump(ctx context.Context, writeTimeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-c.wake:
			if !c.drain(ctx, writeTimeout) {
				return
			}
		}
	}
}

func (c *wsConnection) drain(ctx context.Context, writeTimeout time.Duration) bool {
	for {
		select {
		case envelope := <-c.reliable:
			if !c.write(ctx, envelope, writeTimeout) {
				return false
			}
			continue
		default:
		}

		envelope := c.takeEphemeral()
		if envelope == nil {
			return true
		}
		if !c.write(ctx, envelope, writeTimeout) {
			return false
		}
	}
}

func (c *wsConnection) takeEphemeral() *domain.Envelope {
	c.ephemeralMu.Lock()
	defer c.ephemeralMu.Unlock()

	if len(c.ephemeralOrder) == 0 {
		return nil
	}
	key := c.ephemeralOrder[0]
	c.ephemeralOrder = c.ephemeralOrder[1:]
	envelope := c.ephemeral[key]
	delete(c.ephemeral, key)
	return envelope
}

func (c *wsConnection) write(ctx context.Context, envelope *domain.Envelope, timeout time.Duration) bool {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		// A message we cannot encode is a bug, not a transport failure; drop it
		// rather than tearing down a healthy connection.
		return true
	}

	writeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := c.socket.Write(writeCtx, websocket.MessageText, encoded); err != nil {
		c.Close("write failed")
		return false
	}
	return true
}

func truncateReason(reason string) string {
	// Close frames cap the reason at 123 bytes.
	if len(reason) > 120 {
		return reason[:120]
	}
	return reason
}
