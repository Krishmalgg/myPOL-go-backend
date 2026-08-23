package application

import (
	"encoding/json"

	"mypol/go-realtime/internal/domain"
)

// EventInterestUpdate is the client-to-server report of what a connection
// currently has on screen. Server-consumed, like auth.refresh and the lock
// verbs — never relayed, since a viewport report addressed to the room would
// tell every peer exactly where everybody else is looking for no reason.
const EventInterestUpdate = "interest.update"

// interestUpdatePayload is what the client sends.
type interestUpdatePayload struct {
	PageID string  `json:"pageId"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// InterestService turns a client's viewport report into the index entry the
// relay filters against.
//
// A thin layer over the index, and deliberately so: the interesting decision
// — what routes to whom — belongs to the index and the relay that queries it,
// not here. This exists only to do what every other inbound handler does:
// take identity from the authenticated connection rather than the payload.
type InterestService struct {
	index domain.InterestIndex
}

func NewInterestService(index domain.InterestIndex) *InterestService {
	return &InterestService{index: index}
}

// Update records a connection's viewport, or clears it when the payload
// cannot be parsed — a filter that might be wrong in the sender's favour is
// safer than one built from a malformed rectangle.
func (s *InterestService) Update(connection domain.Connection, payload json.RawMessage) {
	if s == nil || s.index == nil {
		return
	}

	var parsed interestUpdatePayload
	if err := json.Unmarshal(payload, &parsed); err != nil || parsed.PageID == "" ||
		parsed.Width <= 0 || parsed.Height <= 0 {
		s.index.Remove(connection.ID())
		return
	}

	s.index.Update(domain.Interest{
		ConnectionID: connection.ID(),
		// From the authenticated connection, never the payload: a client
		// could otherwise report interest tagged with a note it has no
		// session for, polluting another room's index with entries that can
		// never match any of that room's connections but still cost memory.
		NoteID: connection.NoteID(),
		PageID: parsed.PageID,
		X:      parsed.X,
		Y:      parsed.Y,
		Width:  parsed.Width,
		Height: parsed.Height,
	})
}

// Remove drops a connection's interest — the disconnect path.
func (s *InterestService) Remove(connectionID string) {
	if s == nil || s.index == nil {
		return
	}
	s.index.Remove(connectionID)
}

// Interested answers the routing question for the relay. A nil service (no
// index configured) means unfiltered — the room falls back to broadcasting
// everything, exactly as it did before this feature existed.
func (s *InterestService) Interested(connectionID string, location domain.EventLocation) bool {
	if s == nil || s.index == nil {
		return true
	}
	return s.index.Interested(connectionID, location)
}

func (s *InterestService) Count() int {
	if s == nil || s.index == nil {
		return 0
	}
	return s.index.Count()
}
