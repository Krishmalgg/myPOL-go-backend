package application

import (
	"encoding/json"
	"testing"

	"mypol/go-realtime/internal/domain"
)

func offerTo(target string) *domain.Envelope {
	payload, _ := json.Marshal(map[string]any{
		"target": target,
		"sdp":    "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n",
	})
	return &domain.Envelope{
		V:       domain.EnvelopeVersion,
		Event:   "rtc.offer",
		Payload: payload,
	}
}

// An offer is a private negotiation between two peers. Broadcasting it would
// have every member try to answer, and would leak each peer's SDP to the room.
func TestSignalingReachesOnlyTheNamedPeer(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	target := newFakeConnection("c2", "s2", "u2", "note-1")
	bystander := newFakeConnection("c3", "s3", "u3", "note-1")

	rooms.Join(sender)
	rooms.Join(target)
	rooms.Join(bystander)

	targetBefore := len(target.events(true))
	bystanderBefore := len(bystander.events(true))

	rooms.Relay(sender, offerTo("c2"))

	if got := len(target.events(true)) - targetBefore; got != 1 {
		t.Errorf("target received %d messages, want 1", got)
	}
	if got := len(bystander.events(true)) - bystanderBefore; got != 0 {
		t.Errorf("bystander received %d signalling messages, want 0", got)
	}
}

func TestSignalingIsDroppedWithoutATarget(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	envelope := &domain.Envelope{
		V:       domain.EnvelopeVersion,
		Event:   "rtc.offer",
		Payload: json.RawMessage(`{"sdp":"..."}`),
	}

	reason, delivered := rooms.RelayToPeer(sender, envelope)

	if delivered {
		t.Fatal("an untargeted offer must not be delivered")
	}
	if reason != SignalingNoTarget {
		t.Errorf("reason = %q, want no-target", reason)
	}
}

// The target is chosen by the client, so a sender could otherwise name any
// connection id it has seen and push SDP into a room it is not part of.
func TestSignalingCannotReachAnotherRoom(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	outsider := newFakeConnection("c9", "s9", "u9", "note-2")
	rooms.Join(sender)
	rooms.Join(outsider)

	reason, delivered := rooms.RelayToPeer(sender, offerTo("c9"))

	if delivered {
		t.Fatal("signalling must not cross rooms")
	}
	if reason != SignalingTargetAbsent {
		t.Errorf("reason = %q, want target-not-in-room", reason)
	}
	if len(outsider.events(true)) != 1 {
		t.Error("the outsider should only have its own roster")
	}
}

func TestSignalingRejectsAnAbsentTarget(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	rooms.Join(sender)

	reason, delivered := rooms.RelayToPeer(sender, offerTo("nobody"))

	if delivered || reason != SignalingTargetAbsent {
		t.Fatalf("delivered=%v reason=%q", delivered, reason)
	}
}

func TestSignalingRejectsSelfTarget(t *testing.T) {
	rooms, _ := newRooms()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	rooms.Join(sender)

	reason, delivered := rooms.RelayToPeer(sender, offerTo("c1"))

	if delivered || reason != SignalingSelfTarget {
		t.Fatalf("delivered=%v reason=%q", delivered, reason)
	}
}

// Above the ceiling a mesh costs N² connections while the server relay is
// already open, so the server refuses rather than trusting clients to behave.
func TestSignalingRefusedAboveThePeerLimit(t *testing.T) {
	rooms, _ := newRooms()
	rooms.SetMaxWebRTCPeers(3)

	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	rooms.Join(sender)
	target := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(target)
	rooms.Join(newFakeConnection("c3", "s3", "u3", "note-1"))
	rooms.Join(newFakeConnection("c4", "s4", "u4", "note-1"))

	reason, delivered := rooms.RelayToPeer(sender, offerTo("c2"))

	if delivered {
		t.Fatal("signalling must be refused above the peer limit")
	}
	if reason != SignalingRoomTooLarge {
		t.Errorf("reason = %q, want room-exceeds-peer-limit", reason)
	}
}

func TestSignalingAllowedAtTheLimit(t *testing.T) {
	rooms, _ := newRooms()
	rooms.SetMaxWebRTCPeers(3)

	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	target := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(target)
	rooms.Join(newFakeConnection("c3", "s3", "u3", "note-1"))

	if _, delivered := rooms.RelayToPeer(sender, offerTo("c2")); !delivered {
		t.Fatal("a room exactly at the limit should still allow a mesh")
	}
}

// Every negotiation event routes the same way; answering an offer must not
// suddenly broadcast.
func TestAllNegotiationEventsAreTargeted(t *testing.T) {
	for _, event := range []string{"rtc.offer", "rtc.answer", "rtc.candidate"} {
		t.Run(event, func(t *testing.T) {
			rooms, _ := newRooms()
			sender := newFakeConnection("c1", "s1", "u1", "note-1")
			target := newFakeConnection("c2", "s2", "u2", "note-1")
			bystander := newFakeConnection("c3", "s3", "u3", "note-1")
			rooms.Join(sender)
			rooms.Join(target)
			rooms.Join(bystander)

			before := len(bystander.events(true))
			envelope := offerTo("c2")
			envelope.Event = event
			rooms.Relay(sender, envelope)

			if len(bystander.events(true)) != before {
				t.Fatalf("%s must not reach a bystander", event)
			}
		})
	}
}

func TestSignalingTargetParsing(t *testing.T) {
	if got := domain.SignalingTarget(json.RawMessage(`{"target":"abc"}`)); got != "abc" {
		t.Errorf("target = %q", got)
	}
	if got := domain.SignalingTarget(json.RawMessage(`{"sdp":"x"}`)); got != "" {
		t.Errorf("missing target should be empty, got %q", got)
	}
	// Malformed payloads must not panic or be treated as broadcastable.
	if got := domain.SignalingTarget(json.RawMessage(`not json`)); got != "" {
		t.Errorf("malformed payload should be empty, got %q", got)
	}
}
