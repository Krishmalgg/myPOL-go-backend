package transport

import (
	"encoding/json"
	"errors"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/observability"
)

// blockLockRequest is what a client sends for every lock verb.
//
// The client mints the lockId rather than the server handing one back, so a
// gesture has a correlation id from its first frame — the request, the renews
// and the release all name the same lease without waiting for a round trip.
// It is not a secret and grants nothing on its own: the server binds it to the
// authenticated connection at grant time and refuses any later use by anyone
// else.
type blockLockRequest struct {
	BlockID string `json:"blockId"`
	LockID  string `json:"lockId"`
}

// blockLockHandler answers the three client lock verbs.
//
// Returns true when it consumed the frame, so the caller knows not to relay it.
// These are never relayed: a lock request addressed to the room would let peers
// argue about who holds what, and the point of an arbiter is that there is only
// one answer.
type blockLockHandler func(connection domain.Connection, event string, payload json.RawMessage) bool

func newBlockLockHandler(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
) blockLockHandler {
	return func(connection domain.Connection, event string, payload json.RawMessage) bool {
		switch event {
		case application.EventLockRequest, application.EventLockRenew, application.EventLockRelease:
		default:
			return false
		}
		if locks == nil {
			// Locks are unconfigured. Consuming the frame anyway is deliberate:
			// relaying it would put an unarbitrated request on the wire, and
			// the client already treats silence as "carry on optimistically".
			return true
		}

		var parsed blockLockRequest
		if err := json.Unmarshal(payload, &parsed); err != nil ||
			parsed.BlockID == "" || parsed.LockID == "" {
			deny(rooms, metrics, connection, parsed.BlockID, parsed.LockID, "malformed", nil)
			return true
		}

		switch event {
		case application.EventLockRequest:
			handleLockRequest(locks, rooms, metrics, connection, parsed)
		case application.EventLockRenew:
			handleLockRenew(locks, rooms, metrics, connection, parsed)
		case application.EventLockRelease:
			handleLockRelease(locks, rooms, connection, parsed)
		}
		return true
	}
}

func handleLockRequest(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
	connection domain.Connection,
	parsed blockLockRequest,
) {
	outcome := locks.Request(connection, parsed.BlockID, parsed.LockID)
	if !outcome.Granted() {
		// Holder is nil for a ceiling refusal — nobody else has the block, the
		// caller simply has too many.
		deny(rooms, metrics, connection,
			parsed.BlockID, parsed.LockID, string(outcome.Denial), outcome.Holder)
		return
	}

	granted := application.PublicHolderOf(outcome.Lock)
	if metrics != nil {
		metrics.BlockLocksActive.Store(int64(locks.ActiveLocks()))
	}

	// The requester and the room are told the same thing. Peers need it to grey
	// out their handles, and sending them a different shape would be two
	// protocols for one fact.
	rooms.Notify(connection, application.EventLockGranted, granted)
	rooms.Announce(connection.NoteID(), connection.ID(), application.EventLockGranted, granted)
}

func handleLockRenew(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
	connection domain.Connection,
	parsed blockLockRequest,
) {
	renewed, err := locks.Renew(connection, parsed.BlockID, parsed.LockID)
	if err != nil {
		// A failed renew is a denial, not silence: the holder has to learn its
		// lease is gone, or it will keep dragging a block the room has already
		// released to somebody else.
		reason := "not-held"
		if errors.Is(err, domain.ErrLockNotFound) {
			reason = "expired"
		}
		deny(rooms, metrics, connection, parsed.BlockID, parsed.LockID, reason, nil)
		return
	}

	// Only the holder is told. A renew changes nothing anyone else can observe,
	// so announcing it would be one message per two seconds per active gesture
	// for no benefit.
	rooms.Notify(connection, application.EventLockGranted, application.PublicHolderOf(renewed))
}

func handleLockRelease(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	connection domain.Connection,
	parsed blockLockRequest,
) {
	released, err := locks.Release(connection, parsed.BlockID, parsed.LockID)
	if err != nil {
		// Releasing something already gone is not an error worth reporting: the
		// caller's intent — that it no longer holds the block — is satisfied.
		return
	}
	announceReleased(rooms, application.EventLockReleased, released)
}

// announceReleased tells the whole room a block is free again, the holder
// included: a lease can end without the holder asking (expiry, disconnect,
// eviction), and it must not keep publishing transforms it no longer owns.
func announceReleased(rooms *application.RoomService, event string, lock *domain.BlockLock) {
	rooms.Announce(lock.NoteID, "", event, application.PublicHolderOf(lock))
}

// deny answers the requester alone. A denial is between the server and the
// client that asked; broadcasting it would tell the room who tried and failed
// to move what.
func deny(
	rooms *application.RoomService,
	metrics *observability.Metrics,
	connection domain.Connection,
	blockID, lockID, reason string,
	holder *domain.BlockLock,
) {
	if metrics != nil {
		metrics.BlockLockDenied.Add(1)
	}

	payload := map[string]any{
		"blockId": blockID,
		"lockId":  lockID,
		"reason":  reason,
	}
	if holder != nil {
		// Enough to name the holder in the UI, and nothing more.
		payload["heldBy"] = map[string]any{
			"connectionId": holder.ConnectionID,
			"userId":       holder.UserID,
			"expiresAt":    holder.ExpiresAt.UnixMilli(),
		}
	}
	rooms.Notify(connection, application.EventLockDenied, payload)
}

// releaseLocksOnDisconnect frees everything a departing connection held and
// tells the room.
//
// This is the case the whole lease design exists for. A tab that is closed,
// crashes or loses its network never sends a release, and without this the
// block would stay pinned for the rest of the lease with nobody able to explain
// why. Waiting for expiry would work eventually; announcing immediately means
// the next person can grab it without noticing there was ever a problem.
func releaseLocksOnDisconnect(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
	connectionID string,
) {
	if locks == nil {
		return
	}
	for _, lock := range locks.ReleaseConnection(connectionID) {
		announceReleased(rooms, application.EventLockReleased, lock)
	}
	if metrics != nil {
		metrics.BlockLocksActive.Store(int64(locks.ActiveLocks()))
	}
}

// Geometry events, gated on the lease.
const (
	EventTransformPreview = "block.transform.preview"
	EventTransformCommit  = "block.transform.commit"
)

// newTransformGuard refuses geometry frames from a connection that does not own
// the block's lease.
//
// The two classes are refused differently on purpose. A preview is ephemeral
// and losing one is free, so it is dropped without comment. A commit is final
// state, and the one rule this system may never break is discarding that
// silently — so a refused commit is always answered with an explicit denial the
// client can act on.
func newTransformGuard(
	locks *application.BlockLockService,
	rooms *application.RoomService,
	metrics *observability.Metrics,
) func(domain.Connection, string, json.RawMessage) bool {
	return func(connection domain.Connection, event string, payload json.RawMessage) bool {
		if locks == nil {
			return true
		}
		if event != EventTransformPreview && event != EventTransformCommit {
			return true
		}

		blockID := transformSubject(payload)
		holder, blocked := locks.BlockedBy(connection, blockID)
		if !blocked {
			return true
		}

		if event == EventTransformCommit {
			deny(rooms, metrics, connection, blockID, "", string(domain.DenialHeldByOther), holder)
		}
		return false
	}
}

// transformSubject pulls the block a transform frame is about, so the lease can
// be checked before the frame is relayed.
func transformSubject(payload json.RawMessage) string {
	var fields struct {
		BlockID string `json:"blockId"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return ""
	}
	return fields.BlockID
}
