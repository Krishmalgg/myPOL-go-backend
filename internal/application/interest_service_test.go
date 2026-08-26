package application

import (
	"encoding/json"
	"testing"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
)

func newInterest() *InterestService {
	return NewInterestService(infrastructure.NewMemoryInterestIndex())
}

func TestUpdateTakesTheNoteFromTheConnectionNotThePayload(t *testing.T) {
	service := newInterest()
	// A client on note-1 claiming note-2. Trusting the payload would let one
	// connection's report land in another note's index — a room it has no
	// session for.
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	service.Update(connection, json.RawMessage(`{
		"pageId": "page-1", "x": 0, "y": 0, "width": 100, "height": 100
	}`))

	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 10, Y: 10}) {
		t.Error("the update should have been recorded under the connection's own note")
	}
}

func TestAMalformedPayloadClearsRatherThanCorrupts(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	// A good report first...
	service.Update(connection, json.RawMessage(`{"pageId":"page-1","x":0,"y":0,"width":100,"height":100}`))
	far := domain.GridCellSize * 10
	if service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Fatal("setup: expected the far point to be filtered before the malformed update")
	}

	// ...then a malformed one. A filter built from garbage is worse than no
	// filter at all, so this must fall back to unfiltered rather than keep
	// stale — or worse, zeroed — geometry in effect.
	service.Update(connection, json.RawMessage(`not json`))

	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Error("a malformed report should clear interest back to unfiltered")
	}
}

func TestAnEmptyPageIDIsTreatedAsMalformed(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	service.Update(connection, json.RawMessage(`{"pageId":"","x":0,"y":0,"width":100,"height":100}`))

	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 99999, Y: 99999}) {
		t.Error("a report with no page should not install a filter")
	}
}

func TestANonPositiveViewportIsTreatedAsMalformed(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	service.Update(connection, json.RawMessage(`{"pageId":"page-1","x":0,"y":0,"width":0,"height":100}`))

	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 99999, Y: 99999}) {
		t.Error("a zero-width viewport should not install a usable filter")
	}
}

func TestRemoveDelegatesToTheIndex(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")
	service.Update(connection, json.RawMessage(`{"pageId":"page-1","x":0,"y":0,"width":100,"height":100}`))

	service.Remove("conn-1")

	far := domain.GridCellSize * 10
	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Error("removed interest should fall back to unfiltered")
	}
}

// The zero value is what every construction site gets before SetInterest is
// called, and every one of them must keep working exactly as before this
// feature existed.
func TestANilServiceIsFullyInertRatherThanPanicking(t *testing.T) {
	var service *InterestService

	if !service.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 0, Y: 0}) {
		t.Error("a nil service should mean unfiltered")
	}
	if service.Count() != 0 {
		t.Error("a nil service should report zero tracked connections")
	}

	// Must not panic.
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")
	service.Update(connection, json.RawMessage(`{"pageId":"page-1","x":0,"y":0,"width":10,"height":10}`))
	service.Remove("conn-1")
}

func TestCountReflectsTrackedConnections(t *testing.T) {
	service := newInterest()
	if service.Count() != 0 {
		t.Fatalf("Count() = %d, want 0 initially", service.Count())
	}

	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")
	service.Update(connection, json.RawMessage(`{"pageId":"page-1","x":0,"y":0,"width":10,"height":10}`))
	if service.Count() != 1 {
		t.Errorf("Count() = %d, want 1", service.Count())
	}
}

func TestPreviewPreferencesOnlyFilterTheChosenEphemeralStream(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	service.Update(connection, json.RawMessage(`{
		"pageId":"page-1", "x":0, "y":0, "width":100, "height":100,
		"preview":{"transform":false,"ink":true,"cursor":false,"laser":true}
	}`))

	if service.AllowsPreview(connection.ID(), "block.transform.preview") {
		t.Error("transform preview should be disabled for this recipient")
	}
	if service.AllowsPreview(connection.ID(), "cursor.moved") {
		t.Error("cursor preview should be disabled for this recipient")
	}
	if !service.AllowsPreview(connection.ID(), "ink.points") {
		t.Error("ink preview should remain enabled")
	}
	if !service.AllowsPreview(connection.ID(), "block.transform.commit") {
		t.Error("unknown and durable events must never be filtered by this preference")
	}
}

func TestPartialPreviewPreferencesDefaultMissingStreamsToEnabled(t *testing.T) {
	service := newInterest()
	connection := newFakeConnection("conn-1", "sess-1", "user-1", "note-1")

	service.Update(connection, json.RawMessage(`{
		"pageId":"page-1", "x":0, "y":0, "width":100, "height":100,
		"preview":{"cursor":false}
	}`))

	if service.AllowsPreview(connection.ID(), "cursor.moved") {
		t.Error("explicit false should remain false")
	}
	if !service.AllowsPreview(connection.ID(), "ink.points") {
		t.Error("omitted preview fields should stay enabled for compatibility")
	}
}
