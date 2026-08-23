package application

import (
	"encoding/json"
	"strconv"
	"testing"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
)

// newRoomsWithInterest is newRooms with filtering turned on, for the tests
// that exercise Relay's actual routing decision rather than the index in
// isolation.
func newRoomsWithInterest() (*RoomService, *InterestService) {
	rooms, _ := newRooms()
	interest := NewInterestService(infrastructure.NewMemoryInterestIndex())
	rooms.SetInterest(interest, nil)
	return rooms, interest
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

// This is the whole point of the phase, proven at the layer that actually
// routes traffic: a peer whose reported viewport does not overlap the event's
// position must not receive it.
func TestRelayDoesNotSendEphemeralEventsOutsideAPeersViewport(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	near := newFakeConnection("c2", "s2", "u2", "note-1")
	far := newFakeConnection("c3", "s3", "u3", "note-1")
	rooms.Join(sender)
	rooms.Join(near)
	rooms.Join(far)

	interest.Update(near, mustJSON(t, map[string]any{
		"pageId": "page-1", "x": 0, "y": 0, "width": 100, "height": 100,
	}))
	interest.Update(far, mustJSON(t, map[string]any{
		"pageId": "page-1", "x": 50000, "y": 50000, "width": 100, "height": 100,
	}))

	rooms.Relay(sender, envelopeFor("block.transform.preview",
		`{"blockId":"b1","pageId":"page-1","x":10,"y":10,"width":50,"height":50,"rotation":0}`))

	if len(near.events(false)) != 1 {
		t.Errorf("near peer ephemeral = %v, want the preview", near.events(false))
	}
	if len(far.events(false)) != 0 {
		t.Errorf("far peer ephemeral = %v, want nothing — outside its viewport", far.events(false))
	}
}

// A page id alone is enough to exclude a peer who is looking at a different
// page entirely, even without comparing coordinates.
func TestRelayDoesNotSendEphemeralEventsOnADifferentPage(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	otherPage := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(otherPage)

	interest.Update(otherPage, mustJSON(t, map[string]any{
		"pageId": "page-2", "x": 0, "y": 0, "width": 100, "height": 100,
	}))

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"pageId":"page-1","x":10,"y":10}`))

	if len(otherPage.events(false)) != 0 {
		t.Error("a peer on a different page should not receive the event")
	}
}

// A connection that has not yet sent its first interest.update — every
// connection, for the first moment after it joins — must not have its
// traffic silently dropped while the room waits for a report that has not
// arrived yet.
func TestRelayStillReachesAPeerThatHasNotReportedInterestYet(t *testing.T) {
	rooms, _ := newRoomsWithInterest()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	freshlyJoined := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(freshlyJoined)

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"pageId":"page-1","x":10,"y":10}`))

	if len(freshlyJoined.events(false)) != 1 {
		t.Error("a peer with no reported interest yet must still receive traffic")
	}
}

// Reliable traffic must never be filtered by viewport — a block lock denial
// or a commit has to reach everyone regardless of what they can currently
// see, because the room's correctness depends on it, not just its display.
func TestRelayNeverFiltersReliableTrafficByInterest(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	far := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(far)

	interest.Update(far, mustJSON(t, map[string]any{
		"pageId": "page-2", "x": 99999, "y": 99999, "width": 10, "height": 10,
	}))

	// far already holds its own join roster; count the delta rather than an
	// absolute total.
	before := len(far.events(true))
	rooms.Relay(sender, envelopeFor("block.transform.commit",
		`{"blockId":"b1","pageId":"page-1","operationId":"op1","baseRevision":1,"x":0,"y":0,"width":10,"height":10,"rotation":0}`))

	if len(far.events(true))-before != 1 {
		t.Error("reliable traffic must reach a peer regardless of viewport")
	}
}

// A connection reported disconnected — via the same cleanup path the
// transport layer calls on close — must fall back to receiving everything
// again rather than silently keeping a stale filter forever.
func TestRemovingAConnectionsInterestRestoresUnfilteredDelivery(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	sender := newFakeConnection("c1", "s1", "u1", "note-1")
	peer := newFakeConnection("c2", "s2", "u2", "note-1")
	rooms.Join(sender)
	rooms.Join(peer)

	interest.Update(peer, mustJSON(t, map[string]any{
		"pageId": "page-2", "x": 0, "y": 0, "width": 10, "height": 10,
	}))
	interest.Remove(peer.ID())

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"pageId":"page-1","x":10,"y":10}`))

	if len(peer.events(false)) != 1 {
		t.Error("a peer whose interest was removed should receive traffic unfiltered")
	}
}

// ── large-room scale ─────────────────────────────────────────────────────────
//
// The scenarios the plan asks to be tested: 500 users spread across pages, 500
// spread across viewports on one page, and many users genuinely crowded onto
// one page. fakeConnection is used rather than real sockets — these tests
// exercise the routing decision Relay actually makes, and 500 real WebSocket
// handshakes would test the OS's connection handling, not this feature.

// 500 users across ten pages: an event on one page must reach only the ~50
// users on that page, not the other ~450 who are elsewhere in the note.
func TestFiveHundredUsersAcrossTenPages(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	const users = 500
	const pages = 10
	perPage := users / pages

	peers := make([]*fakeConnection, 0, users)
	for i := 0; i < users; i++ {
		pageID := "page-" + string(rune('0'+(i%pages)))
		peer := newFakeConnection(connID(i), sessID(i), userID(i), "note-1")
		rooms.Join(peer)
		interest.Update(peer, mustJSON(t, map[string]any{
			"pageId": pageID, "x": 0, "y": 0, "width": 500, "height": 500,
		}))
		peers = append(peers, peer)
	}

	sender := newFakeConnection("sender", "sender-s", "sender-u", "note-1")
	rooms.Join(sender)

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"pageId":"page-0","x":10,"y":10}`))

	received := 0
	for i, peer := range peers {
		count := len(peer.events(false))
		onTargetPage := i%pages == 0
		if onTargetPage && count != 1 {
			t.Errorf("peer %d on page-0 got %d events, want 1", i, count)
		}
		if !onTargetPage && count != 0 {
			t.Errorf("peer %d off page-0 got %d events, want 0", i, count)
		}
		received += count
	}
	if received != perPage {
		t.Errorf("total delivered = %d, want exactly the %d peers on page-0", received, perPage)
	}
}

// 500 users on one page, spread across distant viewports: an event must reach
// only those whose reported rectangle actually covers it.
func TestFiveHundredUsersAcrossViewportsOnOnePage(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	const users = 500
	const spread = domain.GridCellSize * 4 // far enough apart to land in different cells

	peers := make([]*fakeConnection, 0, users)
	for i := 0; i < users; i++ {
		peer := newFakeConnection(connID(i), sessID(i), userID(i), "note-1")
		rooms.Join(peer)
		interest.Update(peer, mustJSON(t, map[string]any{
			"pageId": "page-1",
			"x":      float64(i * spread), "y": 0,
			"width": 100, "height": 100,
		}))
		peers = append(peers, peer)
	}

	sender := newFakeConnection("sender", "sender-s", "sender-u", "note-1")
	rooms.Join(sender)

	// An event at peer 250's position: only peers with an overlapping
	// viewport — a small handful around index 250 — should receive it.
	target := 250
	rooms.Relay(sender, envelopeFor("cursor.moved",
		`{"pageId":"page-1","x":`+strconv.Itoa(target*spread)+`,"y":0}`))

	delivered := 0
	for i, peer := range peers {
		count := len(peer.events(false))
		delivered += count
		if count > 0 && absInt(i-target) > 1 {
			t.Errorf("peer %d far from the event received it unexpectedly", i)
		}
	}
	if delivered == 0 {
		t.Error("nobody received an event that was inside their own viewport")
	}
	if delivered == users {
		t.Error("interest filtering had no effect at all — everyone received it")
	}
}

// Many users genuinely crowded onto one small visible area — the case the
// plan calls a hotspot. Filtering by page/cell does not help here (everyone
// overlaps), and it must not break: every one of them still gets exactly one
// copy of the event.
func TestManyUsersCrowdedOnOnePageAllReceiveTheEvent(t *testing.T) {
	rooms, interest := newRoomsWithInterest()
	const users = 300

	peers := make([]*fakeConnection, 0, users)
	for i := 0; i < users; i++ {
		peer := newFakeConnection(connID(i), sessID(i), userID(i), "note-1")
		rooms.Join(peer)
		interest.Update(peer, mustJSON(t, map[string]any{
			"pageId": "page-1", "x": 0, "y": 0, "width": 200, "height": 200,
		}))
		peers = append(peers, peer)
	}

	sender := newFakeConnection("sender", "sender-s", "sender-u", "note-1")
	rooms.Join(sender)

	rooms.Relay(sender, envelopeFor("cursor.moved", `{"pageId":"page-1","x":50,"y":50}`))

	for i, peer := range peers {
		if len(peer.events(false)) != 1 {
			t.Errorf("crowded peer %d got %d events, want exactly 1", i, len(peer.events(false)))
		}
	}
}

func connID(i int) string { return "conn-" + strconv.Itoa(i) }
func sessID(i int) string { return "sess-" + strconv.Itoa(i) }
func userID(i int) string { return "user-" + strconv.Itoa(i) }

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
