package transport

import (
	"encoding/json"
	"testing"

	"github.com/coder/websocket"

	"mypol/go-realtime/internal/application"
	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/testsupport"
)

// readUntil drains server-generated traffic (the roster, presence) until the
// event under test arrives, so a test does not depend on how many housekeeping
// frames precede it.
func readUntil(t *testing.T, socket *websocket.Conn, events ...string) *domain.Envelope {
	t.Helper()
	wanted := make(map[string]struct{}, len(events))
	for _, event := range events {
		wanted[event] = struct{}{}
	}

	for attempt := 0; attempt < 12; attempt++ {
		envelope := readEnvelope(t, socket)
		if _, ok := wanted[envelope.Event]; ok {
			return envelope
		}
	}
	t.Fatalf("never saw any of %v", events)
	return nil
}

func lockPayload(blockID, lockID string) string {
	return `{"blockId":"` + blockID + `","lockId":"` + lockID + `"}`
}

func decodeHolder(t *testing.T, envelope *domain.Envelope) application.PublicHolder {
	t.Helper()
	var holder application.PublicHolder
	if err := json.Unmarshal(envelope.Payload, &holder); err != nil {
		t.Fatalf("decode holder: %v", err)
	}
	return holder
}

func TestLockRequestIsGrantedAndAnnounced(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))

	granted := readUntil(t, ana, application.EventLockGranted)
	if holder := decodeHolder(t, granted); holder.BlockID != "block-1" || holder.LockID != "lock-a" {
		t.Errorf("grant named %+v, want block-1/lock-a", holder)
	}

	// Peers need the grant too, or they have no way to know their handles
	// should be disabled.
	peerView := readUntil(t, ben, application.EventLockGranted)
	if holder := decodeHolder(t, peerView); holder.UserID != "user-ana" {
		t.Errorf("the room should learn who holds it, got %+v", holder)
	}
}

func TestASecondClaimIsDeniedAndNamesTheHolder(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)

	send(t, ben, application.EventLockRequest, lockPayload("block-1", "lock-b"))
	denied := readUntil(t, ben, application.EventLockDenied)

	var payload struct {
		BlockID string `json:"blockId"`
		Reason  string `json:"reason"`
		HeldBy  struct {
			UserID string `json:"userId"`
		} `json:"heldBy"`
	}
	if err := json.Unmarshal(denied.Payload, &payload); err != nil {
		t.Fatalf("decode denial: %v", err)
	}
	if payload.Reason != string(domain.DenialHeldByOther) {
		t.Errorf("reason = %q, want held-by-other", payload.Reason)
	}
	if payload.HeldBy.UserID != "user-ana" {
		t.Errorf("denial should say who holds it, got %q", payload.HeldBy.UserID)
	}
}

// A denial is between the server and the client that asked. Broadcasting it
// would tell the room who tried and failed to move what.
func TestADenialIsNotBroadcastToTheRoom(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)
	readUntil(t, ben, application.EventLockGranted)

	send(t, ben, application.EventLockRequest, lockPayload("block-1", "lock-b"))
	readUntil(t, ben, application.EventLockDenied)

	// Ana's next frame should be her own release echo, never Ben's denial.
	send(t, ana, application.EventLockRelease, lockPayload("block-1", "lock-a"))
	next := readUntil(t, ana, application.EventLockReleased, application.EventLockDenied)
	if next.Event == application.EventLockDenied {
		t.Error("a denial leaked to another member of the room")
	}
}

func TestReleaseTellsTheWholeRoom(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)

	send(t, ana, application.EventLockRelease, lockPayload("block-1", "lock-a"))

	// The holder hears it too: a lease can end without the holder asking, so
	// there is one release path rather than two.
	readUntil(t, ana, application.EventLockReleased)
	readUntil(t, ben, application.EventLockReleased)
}

// A lock request is a question for the arbiter. Relaying it would let peers
// argue about who holds what, and the point of an arbiter is one answer.
func TestLockVerbsAreNeverRelayedToPeers(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))

	seen := readUntil(t, ben,
		application.EventLockGranted, application.EventLockRequest)
	if seen.Event == application.EventLockRequest {
		t.Error("a raw lock request reached a peer")
	}
}

// This is what makes the lease more than a client-side convention: a client
// that ignores its own denial still cannot move the block.
func TestATransformCommitFromANonHolderIsRefusedExplicitly(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)
	readUntil(t, ben, application.EventLockGranted)

	send(t, ben, EventTransformCommit,
		`{"blockId":"block-1","operationId":"op-1","baseRevision":3,"geometry":{"x":10,"y":10}}`)

	// Reliable state is never dropped in silence — the refusal is an answer.
	denied := readUntil(t, ben, application.EventLockDenied, EventTransformCommit)
	if denied.Event != application.EventLockDenied {
		t.Fatal("a commit from a non-holder must be answered with a denial")
	}
}

func TestTheHoldersOwnTransformPasses(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)

	send(t, ana, EventTransformCommit,
		`{"blockId":"block-1","operationId":"op-1","baseRevision":3}`)

	relayed := readUntil(t, ben, EventTransformCommit)
	if relayed.ActorID == nil || *relayed.ActorID != "user-ana" {
		t.Error("the relayed commit should carry the server-stamped actor")
	}
}

// An unlocked block is not a locked one: previews must flow before any grant
// arrives, or every gesture would stall on a round trip.
func TestTransformsFlowFreelyWhenNobodyHoldsTheBlock(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, EventTransformPreview, `{"blockId":"block-free","x":1,"y":2}`)

	readUntil(t, ben, EventTransformPreview)
}

// A viewer may watch a canvas and show a cursor, but must not be able to pin
// somebody else's block by leasing it.
func TestAViewerCannotTakeALock(t *testing.T) {
	h := newWSHarness(t)
	viewer := h.connect(t, testsupport.ClaimsInput{
		UserID: "user-viewer", NoteID: "note-1", Permission: "view",
	})
	editor := h.connect(t, testsupport.ClaimsInput{UserID: "user-editor", NoteID: "note-1"})

	send(t, viewer, application.EventLockRequest, lockPayload("block-1", "lock-v"))

	// The request is refused at the permission gate before it ever reaches the
	// arbiter, so the editor still gets the block.
	send(t, editor, application.EventLockRequest, lockPayload("block-1", "lock-e"))
	granted := readUntil(t, editor, application.EventLockGranted, application.EventLockDenied)
	if granted.Event != application.EventLockGranted {
		t.Fatal("a viewer's request should not have taken the lock")
	}
}

func TestAMalformedLockRequestIsAnswered(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, `{"blockId":""}`)

	readUntil(t, ana, application.EventLockDenied)
}

// The disconnect path, which is the one the lease design exists for: a closed
// tab never sends a release.
func TestClosingAConnectionFreesItsLocks(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})
	ben := h.connect(t, testsupport.ClaimsInput{UserID: "user-ben", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ben, application.EventLockGranted)

	_ = ana.Close(websocket.StatusNormalClosure, "gone")

	released := readUntil(t, ben,
		application.EventLockReleased, application.EventPresenceLeft)
	if released.Event != application.EventLockReleased {
		// Presence may legitimately arrive first; look once more.
		released = readUntil(t, ben, application.EventLockReleased)
	}
	if holder := decodeHolder(t, released); holder.BlockID != "block-1" {
		t.Errorf("released %+v, want block-1", holder)
	}

	if h.locks.ActiveLocks() != 0 {
		t.Errorf("active locks = %d, want 0 after a disconnect", h.locks.ActiveLocks())
	}
}

func TestRenewKeepsTheLeaseWithoutTellingTheRoom(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})

	send(t, ana, application.EventLockRequest, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)

	send(t, ana, application.EventLockRenew, lockPayload("block-1", "lock-a"))
	readUntil(t, ana, application.EventLockGranted)

	if h.locks.ActiveLocks() != 1 {
		t.Errorf("active locks = %d, want 1", h.locks.ActiveLocks())
	}
}

// A renew that fails must be answered. A holder told nothing would keep
// dragging a block the room has already released to somebody else.
func TestAFailedRenewIsDenied(t *testing.T) {
	h := newWSHarness(t)
	ana := h.connect(t, testsupport.ClaimsInput{UserID: "user-ana", NoteID: "note-1"})

	send(t, ana, application.EventLockRenew, lockPayload("block-never-locked", "lock-x"))

	readUntil(t, ana, application.EventLockDenied)
}
