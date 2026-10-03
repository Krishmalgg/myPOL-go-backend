package transport

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mypol/go-realtime/internal/domain"
)

var errReliableQueueFull = errors.New("reliable queue full")

// outboundQueues is the send-side buffering every transport shares.
//
// Extracted rather than duplicated per transport: the *policy* — ephemeral
// frames coalesce and shed, reliable frames queue and refuse — is a property of
// the traffic, not of the wire underneath it. WebSocket and WebTransport differ
// only in how they write a frame, never in which frame should be written next.
type outboundQueues struct {
	ephemeralMu    sync.Mutex
	ephemeral      map[string]*domain.Envelope
	ephemeralOrder []string
	maxEphemeral   int
	dropped        uint64
	// droppedInk is the subset of dropped that was live ink. A superseded
	// cursor is the design working; a lost ink frame is a visible gap in
	// someone's line, so the two must not share one number.
	droppedInk uint64

	// reliable is bounded and refuses rather than discarding.
	reliable chan *domain.Envelope
	// reliableInFlight keeps graceful shutdown from mistaking a frame currently
	// being written for a fully drained queue.
	reliableInFlight atomic.Int32

	// wake nudges the writer without ever blocking a sender.
	wake chan struct{}

	closeOnce sync.Once
	closed    chan struct{}
	// closeReason is the first reason given, so the disconnect log says why the
	// connection ended rather than which deferred cleanup ran last.
	closeReason string

	// lastActivity is when the client last sent anything (unix nanoseconds),
	// for transports that cannot use one read deadline (WebTransport reads
	// datagrams and a stream separately). lastTouch throttles session touches.
	lastActivity atomic.Int64
	lastTouch    atomic.Int64
}

// markActivity records that the client sent something.
func (q *outboundQueues) markActivity(now time.Time) { q.lastActivity.Store(now.UnixNano()) }

// idleFor is how long the client has been silent.
func (q *outboundQueues) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, q.lastActivity.Load()))
}

// shouldTouch reports, at most once per interval, that the session's liveness
// should be recorded. Ink arrives many times a second; the session store only
// needs to hear about it occasionally.
func (q *outboundQueues) shouldTouch(now time.Time, interval time.Duration) bool {
	last := q.lastTouch.Load()
	if now.UnixNano()-last < int64(interval) {
		return false
	}
	return q.lastTouch.CompareAndSwap(last, now.UnixNano())
}

func newOutboundQueues(ephemeralSize, reliableSize int) *outboundQueues {
	return &outboundQueues{
		ephemeral:    make(map[string]*domain.Envelope, ephemeralSize),
		maxEphemeral: ephemeralSize,
		reliable:     make(chan *domain.Envelope, reliableSize),
		wake:         make(chan struct{}, 1),
		closed:       make(chan struct{}),
	}
}

func (q *outboundQueues) isClosed() bool {
	select {
	case <-q.closed:
		return true
	default:
		return false
	}
}

// markClosed is idempotent, so a transport may call it from both its read and
// write paths without risking a double close.
func (q *outboundQueues) markClosed() { q.markClosedWith("") }

// markClosedWith records the reason only on the first close.
func (q *outboundQueues) markClosedWith(reason string) {
	q.closeOnce.Do(func() {
		q.closeReason = reason
		close(q.closed)
	})
}

// CloseReason is the reason given by whichever path closed the connection
// first. Read it only after the connection is closed.
func (q *outboundQueues) CloseReason() string {
	if !q.isClosed() {
		return ""
	}
	return q.closeReason
}

// pushReliable queues a message that must arrive.
//
// Refusing rather than blocking is deliberate: blocking would stall whichever
// goroutine is fanning out to the whole room, letting one slow client freeze
// everyone else.
func (q *outboundQueues) pushReliable(envelope *domain.Envelope) error {
	if q.isClosed() {
		return nil
	}

	select {
	case q.reliable <- envelope:
		q.signal()
		return nil
	default:
		return errReliableQueueFull
	}
}

// pushEphemeral queues a droppable frame, replacing any queued frame with the
// same key so a slow reader sheds staleness instead of accumulating a backlog.
func (q *outboundQueues) pushEphemeral(envelope *domain.Envelope, coalesceKey string) {
	if q.isClosed() {
		return
	}

	q.ephemeralMu.Lock()
	if existing, exists := q.ephemeral[coalesceKey]; exists {
		q.countDrop(existing)
	} else {
		q.ephemeralOrder = append(q.ephemeralOrder, coalesceKey)
	}
	q.ephemeral[coalesceKey] = envelope

	// Under sustained pressure shed the oldest stream: an ancient cursor
	// position is worth less than a current one.
	for len(q.ephemeralOrder) > q.maxEphemeral {
		oldest := q.ephemeralOrder[0]
		q.ephemeralOrder = q.ephemeralOrder[1:]
		q.countDrop(q.ephemeral[oldest])
		delete(q.ephemeral, oldest)
	}
	q.ephemeralMu.Unlock()

}

// takeReliable returns the next reliable frame, if any, without blocking.
func (q *outboundQueues) takeReliable() *domain.Envelope {
	select {
	case envelope := <-q.reliable:
		return envelope
	default:
		return nil
	}
}

// PendingReliable is intentionally only the bounded queue depth. A writer may
// have one frame in flight, but it is already being handed to the socket/stream
// and must not keep graceful shutdown waiting forever on a slow peer.
func (q *outboundQueues) PendingReliable() int {
	return len(q.reliable) + int(q.reliableInFlight.Load())
}

func (q *outboundQueues) PendingEphemeral() int {
	q.ephemeralMu.Lock()
	defer q.ephemeralMu.Unlock()
	return len(q.ephemeralOrder)
}

func (q *outboundQueues) beginReliableWrite() { q.reliableInFlight.Add(1) }
func (q *outboundQueues) endReliableWrite()   { q.reliableInFlight.Add(-1) }

// takeEphemeral returns the oldest queued stream's newest frame.
func (q *outboundQueues) takeEphemeral() *domain.Envelope {
	q.ephemeralMu.Lock()
	defer q.ephemeralMu.Unlock()

	if len(q.ephemeralOrder) == 0 {
		return nil
	}
	key := q.ephemeralOrder[0]
	q.ephemeralOrder = q.ephemeralOrder[1:]
	envelope := q.ephemeral[key]
	delete(q.ephemeral, key)
	return envelope
}

// takeEphemeralBatch drains up to limit newest frames in their queue order.
// The writer calls this once per short flush window, so one slow recipient
// receives one aggregate rather than a burst of individual WebSocket writes.
func (q *outboundQueues) takeEphemeralBatch(limit int) []*domain.Envelope {
	if limit <= 0 {
		return nil
	}
	q.ephemeralMu.Lock()
	defer q.ephemeralMu.Unlock()

	count := min(limit, len(q.ephemeralOrder))
	if count == 0 {
		return nil
	}
	batch := make([]*domain.Envelope, 0, count)
	for _, key := range q.ephemeralOrder[:count] {
		if envelope := q.ephemeral[key]; envelope != nil {
			batch = append(batch, envelope)
			delete(q.ephemeral, key)
		}
	}
	q.ephemeralOrder = q.ephemeralOrder[count:]
	return batch
}

func (q *outboundQueues) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// countDrop records one discarded frame. Called with ephemeralMu held.
func (q *outboundQueues) countDrop(envelope *domain.Envelope) {
	q.dropped++
	if envelope != nil && strings.HasPrefix(envelope.Event, "ink.") {
		q.droppedInk++
	}
}

// Dropped reports frames discarded by coalescing or shedding — a health signal
// worth surfacing, since silent loss is the whole point of the ephemeral queue.
func (q *outboundQueues) Dropped() uint64 {
	q.ephemeralMu.Lock()
	defer q.ephemeralMu.Unlock()
	return q.dropped
}

// DroppedInk reports the ink frames among Dropped.
func (q *outboundQueues) DroppedInk() uint64 {
	q.ephemeralMu.Lock()
	defer q.ephemeralMu.Unlock()
	return q.droppedInk
}
