package transport

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"

	"mypol/go-realtime/internal/codec"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
)

// MaxFramePrefix bounds a length-prefixed stream frame. A hostile or corrupt
// prefix must not be able to make the server allocate arbitrarily.
const MaxFramePrefix = 1 << 20 // 1 MiB

// wtConnection is one authenticated WebTransport session.
//
// This is where WebTransport earns its place: ephemeral frames go out as
// **datagrams**, which may be dropped and reordered by the network but never
// head-of-line block, while reliable frames go out on a single long-lived
// **stream**. A cursor position that arrives late is worse than one that never
// arrives, and a stroke commit is the opposite — one transport, two guarantees.
//
// The stream writer is created once and reused. Opening a stream per message
// would add a round trip to every commit and defeat the point.
type wtConnection struct {
	*outboundQueues

	id        string
	sessionID string
	userID    string
	noteID    string

	mu              sync.RWMutex
	permission      domain.Permission
	binaryFrames    bool
	aggregateFrames bool

	session *webtransport.Session
	metrics *observability.Metrics

	// streamMu serialises writes: a QUIC stream is a single byte sequence, so
	// two concurrent writers would interleave frames into nonsense.
	streamMu sync.Mutex
	stream   *webtransport.Stream

	// maxDatagram is the runtime's advertised datagram capacity. Frames above
	// it fall back to the reliable stream rather than being silently dropped.
	maxDatagram int

	connectedAt time.Time
}

func newWTConnection(
	id string,
	ticket *domain.ConnectionTicket,
	session *webtransport.Session,
	stream *webtransport.Stream,
	ephemeralQueueSize, reliableQueueSize, maxDatagram int,
	metrics *observability.Metrics,
	now time.Time,
) *wtConnection {
	return &wtConnection{
		outboundQueues: newOutboundQueues(ephemeralQueueSize, reliableQueueSize),
		id:             id,
		sessionID:      ticket.SessionID,
		userID:         ticket.UserID,
		noteID:         ticket.NoteID,
		permission:     ticket.Permission,
		session:        session,
		metrics:        metrics,
		stream:         stream,
		maxDatagram:    maxDatagram,
		connectedAt:    now,
	}
}

func (c *wtConnection) ID() string             { return c.id }
func (c *wtConnection) SessionID() string      { return c.sessionID }
func (c *wtConnection) UserID() string         { return c.userID }
func (c *wtConnection) NoteID() string         { return c.noteID }
func (c *wtConnection) ConnectedAt() time.Time { return c.connectedAt }

func (c *wtConnection) Permission() domain.Permission {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.permission
}

func (c *wtConnection) SetPermission(permission domain.Permission) {
	c.mu.Lock()
	c.permission = permission
	c.mu.Unlock()
}

func (c *wtConnection) EnableBinaryFrames() {
	c.mu.Lock()
	c.binaryFrames = true
	c.mu.Unlock()
}

func (c *wtConnection) EnableBinaryAggregates() {
	c.mu.Lock()
	c.aggregateFrames = true
	c.mu.Unlock()
}

func (c *wtConnection) supportsBinaryFrames() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryFrames
}

func (c *wtConnection) supportsBinaryAggregates() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryFrames && c.aggregateFrames
}

func (c *wtConnection) SendReliable(envelope *domain.Envelope) error {
	err := c.pushReliable(envelope)
	if err != nil && c.metrics != nil {
		c.metrics.ReliableOverflow.Add(1)
	}
	if c.metrics != nil {
		c.metrics.ObserveQueueDepth(c.PendingReliable(), c.PendingEphemeral())
	}
	return err
}

func (c *wtConnection) SendEphemeral(envelope *domain.Envelope, coalesceKey string) {
	droppedBefore := c.Dropped()
	c.pushEphemeral(envelope, coalesceKey)
	if c.metrics != nil {
		c.metrics.DroppedEphemeral.Add(int64(c.Dropped() - droppedBefore))
		c.metrics.ObserveQueueDepth(c.PendingReliable(), c.PendingEphemeral())
	}
}

func (c *wtConnection) PendingReliable() int { return c.outboundQueues.PendingReliable() }

func (c *wtConnection) Close(reason string) {
	alreadyClosed := c.isClosed()
	c.markClosed()
	if alreadyClosed {
		return
	}
	_ = c.session.CloseWithError(0, truncateReason(reason))
}

// writePump is the only goroutine that writes to this session.
func (c *wtConnection) writePump(ctx context.Context) {
	ticker := time.NewTicker(ephemeralFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-c.wake:
			if !c.drainReliable() {
				return
			}
		case <-ticker.C:
			if !c.drainEphemeral() {
				return
			}
		}
	}
}

func (c *wtConnection) drainReliable() bool {
	for {
		// Reliable first: a commit must not wait behind cursor frames.
		if envelope := c.takeReliable(); envelope != nil {
			c.beginReliableWrite()
			written := c.writeStream(envelope)
			c.endReliableWrite()
			if !written {
				return false
			}
			continue
		}

		return true
	}
}

func (c *wtConnection) drainEphemeral() bool {
	for {
		batch := c.takeEphemeralBatch(maxEphemeralAggregateFrames)
		if len(batch) == 0 {
			return true
		}
		if len(batch) > 1 && c.supportsBinaryAggregates() {
			if encoded, ok := codec.EncodeRelayAggregate(batch); ok && (c.maxDatagram <= 0 || len(encoded) <= c.maxDatagram) {
				_ = c.session.SendDatagram(encoded)
				continue
			}
		}
		for _, envelope := range batch {
			c.writeDatagram(envelope)
		}
	}
}

// writeDatagram sends a preview frame, falling back to the stream when the
// frame exceeds what the runtime will carry in a datagram.
func (c *wtConnection) writeDatagram(envelope *domain.Envelope) {
	encoded := c.wireBytes(envelope)
	if encoded == nil {
		return
	}

	if c.maxDatagram > 0 && len(encoded) > c.maxDatagram {
		// Too big for a datagram. Preview traffic is droppable, but sending it
		// reliably is strictly better than losing it for a size reason.
		c.writeStream(envelope)
		return
	}

	if err := c.session.SendDatagram(encoded); err != nil {
		// Datagrams are best-effort by definition; a failure here is not a
		// reason to tear down an otherwise healthy session.
		return
	}
	if c.metrics != nil {
		c.metrics.MessagesOut.Add(1)
		c.metrics.OutgoingBytes.Add(int64(len(encoded)))
	}
}

// writeStream sends a frame on the shared reliable stream, length-prefixed.
//
// A QUIC stream is a byte sequence with no message boundaries, so the receiver
// cannot tell where one envelope ends without an explicit length.
func (c *wtConnection) writeStream(envelope *domain.Envelope) bool {
	encoded := c.wireBytes(envelope)
	if encoded == nil {
		return true
	}
	return c.writeStreamBytes(encoded)
}

func (c *wtConnection) writeStreamBytes(encoded []byte) bool {

	frame := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(encoded)))
	copy(frame[4:], encoded)

	c.streamMu.Lock()
	_, writeErr := c.stream.Write(frame)
	c.streamMu.Unlock()

	if writeErr != nil {
		c.Close("stream write failed")
		return false
	}
	if c.metrics != nil {
		c.metrics.MessagesOut.Add(1)
		c.metrics.OutgoingBytes.Add(int64(len(frame)))
	}
	return true
}

// A WebTransport stream is only a fallback for an oversize preview here;
// normal reliable operations still select JSON because their event class is
// not ephemeral.
func (c *wtConnection) wireBytes(envelope *domain.Envelope) []byte {
	if c.supportsBinaryFrames() && domain.ClassifyEvent(envelope.Event) == domain.ClassEphemeral {
		if encoded, ok := codec.EncodeRelayFrame(envelope); ok {
			return encoded
		}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	return encoded
}

// readStreamFrames yields length-prefixed frames from the client's stream.
func readStreamFrames(stream io.Reader, onFrame func([]byte)) error {
	header := make([]byte, 4)
	for {
		if _, err := io.ReadFull(stream, header); err != nil {
			return err
		}

		size := binary.BigEndian.Uint32(header)
		if size == 0 {
			continue
		}
		if size > MaxFramePrefix {
			// Refuse rather than allocate what a bad prefix asks for.
			return io.ErrUnexpectedEOF
		}

		payload := make([]byte, size)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return err
		}
		onFrame(payload)
	}
}
