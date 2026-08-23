package transport

import (
	"encoding/json"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/codec"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
	"mypol/go-realtime/internal/security"
)

// binaryFrameConnection is deliberately a narrow optional capability rather
// than an addition to domain.Connection. Rooms do not care about wire format;
// only a concrete transport learns that its browser proved binary support.
type binaryFrameConnection interface {
	EnableBinaryFrames()
}

type aggregateFrameConnection interface {
	EnableBinaryAggregates()
}

// Client-to-server control events, handled rather than relayed.
const (
	EventAuthRefresh          = "auth.refresh"
	EventAuthRefreshed        = "auth.refreshed"
	EventAuthRejected         = "auth.rejected"
	EventProtocolCapabilities = "protocol.capabilities"
)

// handleClientFrame validates one inbound client message and relays it.
//
// Shared by every transport: what makes a frame acceptable is a property of the
// protocol, not of the wire. A rule enforced for WebSocket but forgotten for
// WebTransport would be a permission bypass reachable by simply choosing the
// other transport, so there is exactly one implementation.
//
// Order matters. Parse, then rate limit, then authorise, then stamp:
// rate-limiting ahead of the permission check stops a client using rejected
// messages as a free channel to probe what it is allowed to send.
func handleClientFrame(
	deps frameDeps,
	connection domain.Connection,
	limits *security.RateLimits,
	data []byte,
) {
	if deps.acceptApplicationWrites != nil && !deps.acceptApplicationWrites() {
		// A draining server must not accept a late lock/commit merely because
		// the socket was established before readiness changed.
		return
	}
	if deps.metrics != nil {
		deps.metrics.MessagesIn.Add(1)
		deps.metrics.IncomingBytes.Add(int64(len(data)))
	}

	var envelope domain.Envelope
	if codec.IsBinaryFrame(data) {
		decoded, err := codec.DecodeClientFrame(data)
		if err != nil {
			return
		}
		envelope = *decoded
		// This is a capability probe, not a client claim in an envelope. Older
		// clients continue receiving JSON; once a browser has sent one valid
		// binary preview it can receive compact relayed previews as well.
		if binaryConnection, ok := connection.(binaryFrameConnection); ok {
			binaryConnection.EnableBinaryFrames()
		}
	} else if err := json.Unmarshal(data, &envelope); err != nil || envelope.Event == "" {
		return
	}

	class := domain.ClassifyEvent(envelope.Event)
	now := deps.now()

	if !limits.Allow(class, now) {
		deps.debug("rate limited", "connectionId", connection.ID(), "event", envelope.Event)
		return
	}

	if !connection.Permission().MayPublish(envelope.Event) {
		deps.debug("permission denied",
			"connectionId", connection.ID(),
			"event", envelope.Event,
			"permission", connection.Permission().String())
		return
	}

	// auth.refresh is addressed to the server, not to the room. Relaying it
	// would hand every peer a bearer token.
	if envelope.Event == EventAuthRefresh {
		deps.authRefresh(connection, envelope.Payload)
		return
	}

	// A capability frame is consumed by the transport. It must never reach the
	// room, because it describes this recipient's decoder rather than canvas
	// state. The existing v1 binary capability stays separate for compatibility.
	if envelope.Event == EventProtocolCapabilities {
		var capability struct {
			BinaryAggregateVersion int `json:"binaryAggregateVersion"`
		}
		if json.Unmarshal(envelope.Payload, &capability) == nil && capability.BinaryAggregateVersion >= 1 {
			if aggregateConnection, ok := connection.(aggregateFrameConnection); ok {
				aggregateConnection.EnableBinaryAggregates()
			}
		}
		return
	}

	// A viewport report is for the interest index alone. Relaying it would
	// broadcast exactly where this connection is looking to everyone else on
	// the note — a routing optimisation must not become a surveillance feed.
	if deps.interestUpdate != nil && envelope.Event == application.EventInterestUpdate {
		deps.interestUpdate(connection, envelope.Payload)
		return
	}

	// Lock verbs are questions for the arbiter, not announcements to the room.
	if deps.blockLock != nil && deps.blockLock(connection, envelope.Event, envelope.Payload) {
		return
	}

	// A geometry lease is only real if the server enforces it. Without this a
	// client that ignored its own denial could still drag the block, and the
	// lock would be a suggestion rather than a rule.
	if deps.transformGuard != nil && !deps.transformGuard(connection, envelope.Event, envelope.Payload) {
		return
	}

	// Identity and channel come from the authenticated connection, never from
	// the client's own claims — otherwise a client could publish into another
	// note's room or forge another user's cursor.
	envelope.Stamp(connection.SessionID(), connection.ID(), connection.UserID(), now.UnixMilli())
	envelope.Channel = "note:" + connection.NoteID()
	if envelope.MessageID == "" {
		envelope.MessageID = deps.newID()
	}

	deps.relay(connection, &envelope)
}

// newInterestUpdateHandler records a connection's reported viewport.
//
// Unlike auth.refresh and the lock verbs, this has no reply: the client
// already applied its own viewport optimistically and has nothing to wait
// for. A nil interest service (filtering unconfigured) means the handler is
// never installed at all — see frameDeps — so this only exists once there is
// somewhere for the report to go.
func newInterestUpdateHandler(
	interest *application.InterestService,
	metrics *observability.Metrics,
) func(domain.Connection, json.RawMessage) {
	return func(connection domain.Connection, payload json.RawMessage) {
		interest.Update(connection, payload)
		if metrics != nil {
			metrics.InterestUpdatesTotal.Add(1)
		}
	}
}
