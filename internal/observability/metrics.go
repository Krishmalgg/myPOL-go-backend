// Package observability holds the service's counters.
//
// Deliberately dependency-free rather than pulling in a Prometheus client:
// nothing here needs a registry or a scrape format yet, and an interface this
// small can be swapped for one later without touching a call site. What matters
// now is that the numbers exist and are cheap enough to record on a hot path.
package observability

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// Metrics counts what the plan asks to measure. Every field is an atomic, so
// recording never takes a lock on the relay path.
type Metrics struct {
	ActiveSessions    atomic.Int64
	ActiveConnections atomic.Int64
	ActiveRooms       atomic.Int64

	MessagesIn  atomic.Int64
	MessagesOut atomic.Int64
	IncomingBytes atomic.Int64
	OutgoingBytes atomic.Int64

	// DroppedEphemeral is expected to be non-zero under load — shedding stale
	// previews is the design working, not a fault. It matters as a rate, not
	// as a total.
	DroppedEphemeral atomic.Int64
	// ReliableOverflow is the opposite: any value above zero means a client was
	// disconnected because final state could not be delivered.
	ReliableOverflow atomic.Int64
	// Queue depths are high-water marks rather than a global instantaneous
	// gauge. A single point-in-time sample cannot describe a burst; the largest
	// per-connection depth reached during a run can.
	ReliableQueueDepthMax  atomic.Int64
	EphemeralQueueDepthMax atomic.Int64

	RateLimited      atomic.Int64
	PermissionDenied atomic.Int64

	SessionAuthFailures atomic.Int64
	HMACAuthFailures    atomic.Int64
	BootstrapThrottled  atomic.Int64

	TicketsIssued   atomic.Int64
	TicketsConsumed atomic.Int64
	TicketsExpired  atomic.Int64

	SignalingRelayed atomic.Int64
	SignalingRefused atomic.Int64

	AuthRefreshAccepted atomic.Int64
	AuthRefreshRejected atomic.Int64

	// BlockLocksActive is a gauge, not a counter: it is set from the store's
	// own count rather than incremented, so a missed decrement cannot make it
	// drift upward forever.
	BlockLocksActive atomic.Int64
	BlockLockDenied  atomic.Int64

	// InterestUpdatesTotal counts viewport reports received — how often
	// clients are actually reporting, distinct from how well the reports work.
	InterestUpdatesTotal atomic.Int64
	// InterestEventsTotal and InterestRecipientsTotal are accumulated
	// separately so a snapshot can divide one by the other for an average
	// recipients-per-event rate, which is the number the plan actually asks
	// to observe — a raw recipient total alone says nothing about any one
	// event.
	InterestEventsTotal     atomic.Int64
	InterestRecipientsTotal atomic.Int64
	// InterestFilteredTotal counts peers an event was *not* sent to because
	// their reported interest excluded it — the fan-out this whole feature
	// exists to avoid, made visible as a number.
	InterestFilteredTotal atomic.Int64
}

func New() *Metrics { return &Metrics{} }

// Snapshot is the JSON shape served by the metrics endpoint.
type Snapshot struct {
	ActiveSessions    int64 `json:"activeSessions"`
	ActiveConnections int64 `json:"activeConnections"`
	ActiveRooms       int64 `json:"activeRooms"`

	MessagesIn  int64 `json:"messagesInTotal"`
	MessagesOut int64 `json:"messagesOutTotal"`
	IncomingBytes int64 `json:"incomingBytesTotal"`
	OutgoingBytes int64 `json:"outgoingBytesTotal"`

	DroppedEphemeral int64 `json:"droppedEphemeralTotal"`
	ReliableOverflow int64 `json:"reliableOverflowTotal"`
	ReliableQueueDepthMax  int64 `json:"reliableQueueDepthMax"`
	EphemeralQueueDepthMax int64 `json:"ephemeralQueueDepthMax"`

	RateLimited      int64 `json:"rateLimitedTotal"`
	PermissionDenied int64 `json:"permissionDeniedTotal"`

	SessionAuthFailures int64 `json:"sessionAuthFailuresTotal"`
	HMACAuthFailures    int64 `json:"hmacAuthFailuresTotal"`
	BootstrapThrottled  int64 `json:"bootstrapThrottledTotal"`

	TicketsIssued   int64 `json:"connectionTicketsIssuedTotal"`
	TicketsConsumed int64 `json:"connectionTicketsConsumedTotal"`
	TicketsExpired  int64 `json:"connectionTicketsExpiredTotal"`

	SignalingRelayed int64 `json:"webrtcSignalingRelayedTotal"`
	SignalingRefused int64 `json:"webrtcSignalingRefusedTotal"`

	AuthRefreshAccepted int64 `json:"authRefreshAcceptedTotal"`
	AuthRefreshRejected int64 `json:"authRefreshRejectedTotal"`

	BlockLocksActive int64 `json:"activeBlockLocks"`
	BlockLockDenied  int64 `json:"blockLockDeniedTotal"`

	InterestUpdatesTotal    int64 `json:"interestUpdatesTotal"`
	InterestEventsTotal     int64 `json:"interestEventsTotal"`
	InterestRecipientsTotal int64 `json:"interestRecipientsTotal"`
	InterestFilteredTotal   int64 `json:"interestFilteredRecipientsTotal"`
	// RecipientsPerEvent is derived at snapshot time rather than stored, so it
	// is never subject to the two counters it divides drifting out of step —
	// there is nothing to keep in sync because it is computed fresh from
	// whatever they currently hold.
	InterestRecipientsPerEvent float64 `json:"interestRecipientsPerEvent"`
}

func (m *Metrics) Snapshot() Snapshot {
	snapshot := Snapshot{
		ActiveSessions:      m.ActiveSessions.Load(),
		ActiveConnections:   m.ActiveConnections.Load(),
		ActiveRooms:         m.ActiveRooms.Load(),
		MessagesIn:          m.MessagesIn.Load(),
		MessagesOut:         m.MessagesOut.Load(),
		IncomingBytes:       m.IncomingBytes.Load(),
		OutgoingBytes:       m.OutgoingBytes.Load(),
		DroppedEphemeral:    m.DroppedEphemeral.Load(),
		ReliableOverflow:    m.ReliableOverflow.Load(),
		ReliableQueueDepthMax:  m.ReliableQueueDepthMax.Load(),
		EphemeralQueueDepthMax: m.EphemeralQueueDepthMax.Load(),
		RateLimited:         m.RateLimited.Load(),
		PermissionDenied:    m.PermissionDenied.Load(),
		SessionAuthFailures: m.SessionAuthFailures.Load(),
		HMACAuthFailures:    m.HMACAuthFailures.Load(),
		BootstrapThrottled:  m.BootstrapThrottled.Load(),
		TicketsIssued:       m.TicketsIssued.Load(),
		TicketsConsumed:     m.TicketsConsumed.Load(),
		TicketsExpired:      m.TicketsExpired.Load(),
		SignalingRelayed:    m.SignalingRelayed.Load(),
		SignalingRefused:    m.SignalingRefused.Load(),
		AuthRefreshAccepted: m.AuthRefreshAccepted.Load(),
		AuthRefreshRejected: m.AuthRefreshRejected.Load(),
		BlockLocksActive:    m.BlockLocksActive.Load(),
		BlockLockDenied:     m.BlockLockDenied.Load(),

		InterestUpdatesTotal:    m.InterestUpdatesTotal.Load(),
		InterestEventsTotal:     m.InterestEventsTotal.Load(),
		InterestRecipientsTotal: m.InterestRecipientsTotal.Load(),
		InterestFilteredTotal:   m.InterestFilteredTotal.Load(),
	}
	if snapshot.InterestEventsTotal > 0 {
		snapshot.InterestRecipientsPerEvent =
			float64(snapshot.InterestRecipientsTotal) / float64(snapshot.InterestEventsTotal)
	}
	return snapshot
}

// ObserveQueueDepth records a maximum without a relay-path mutex. The caller
// supplies its own queue's current depth, so this metric stays useful even
// while hundreds of independent connection queues are active.
func (m *Metrics) ObserveQueueDepth(reliable, ephemeral int) {
	observeMax(&m.ReliableQueueDepthMax, int64(reliable))
	observeMax(&m.EphemeralQueueDepthMax, int64(ephemeral))
}

func observeMax(target *atomic.Int64, value int64) {
	for {
		current := target.Load()
		if value <= current || target.CompareAndSwap(current, value) {
			return
		}
	}
}

// Handler serves the snapshot as JSON.
//
// No identifiers are exposed — only counts. Session ids, note ids and user ids
// belong in logs where access is controlled, never on an endpoint whose whole
// purpose is to be scraped.
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	}
}
