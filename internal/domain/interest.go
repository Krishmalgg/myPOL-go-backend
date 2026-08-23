package domain

import "encoding/json"

// GridCellSize is the side length of a uniform grid cell, in canvas units
// (the same coordinate space block geometry already uses).
//
// A page is typically a few hundred to a couple of thousand units on a side,
// so this yields a small, fixed number of cells per page rather than one per
// pixel — coarse enough that a connection's interest rarely needs updating as
// it pans, fine enough that a stroke on one side of a large page does not
// reach a viewer looking at the other side.
const GridCellSize = 512

// Interest is what one connection currently cares about: a page, and the
// rectangle of it currently on screen.
//
// This is reported by the client, not measured by the server — Go has no way
// to know what a browser has rendered, so the viewport is deliberately a
// self-report. A client that lies only ever hurts itself: interest is a
// routing optimisation, never a security boundary, so a wrong or malicious
// report at worst causes that one connection to miss traffic it wanted or
// receive traffic it did not, and never grants access to anything permission
// would not already allow.
type Interest struct {
	ConnectionID string
	NoteID       string
	PageID       string

	// The visible rectangle in page-relative canvas units — the same space
	// block geometry already lives in, so no conversion is needed to test
	// whether an event's position falls inside it.
	X      float64
	Y      float64
	Width  float64
	Height float64
}

// Cells returns the grid cells this interest's rectangle overlaps, expanded by
// one cell of margin on every side.
//
// The margin exists because interest updates are coalesced and therefore
// stale by construction — a viewport that has panned since its last report
// would otherwise have a visible sliver just outside its known cells receive
// nothing until the next update lands. One cell of slack absorbs that lag
// without requiring every pan pixel to be reported.
func (i Interest) Cells() []GridCell {
	if i.Width <= 0 || i.Height <= 0 {
		return nil
	}

	minCellX := cellIndex(i.X) - 1
	minCellY := cellIndex(i.Y) - 1
	maxCellX := cellIndex(i.X+i.Width) + 1
	maxCellY := cellIndex(i.Y+i.Height) + 1

	cells := make([]GridCell, 0, (maxCellX-minCellX+1)*(maxCellY-minCellY+1))
	for cx := minCellX; cx <= maxCellX; cx++ {
		for cy := minCellY; cy <= maxCellY; cy++ {
			cells = append(cells, GridCell{X: cx, Y: cy})
		}
	}
	return cells
}

func cellIndex(coordinate float64) int {
	return int(coordinate) / GridCellSize
}

// GridCell identifies one cell of the uniform grid within a page.
//
// Deliberately not a quadtree: the plan calls for starting with the simplest
// structure that solves the fan-out problem, and a fixed grid is exactly that
// — O(1) cell lookup for any point, no rebalancing, no tree to get wrong.
// Revisit only if a real workload's cell occupancy turns out to be lopsided
// enough that a uniform grid stops being cheap to scan.
type GridCell struct {
	X int
	Y int
}

// EventLocation is where one ephemeral event happened, extracted from its own
// payload rather than trusted from any separate claim.
//
// PageID and the point are independent: an event may report a page with no
// point (an `ink.points` continuation, which carries only a stroke id and
// relies on the cell its `ink.started` already established) or, in principle,
// neither. The router degrades gracefully in both cases — see
// `InterestIndex.Interested`.
type EventLocation struct {
	PageID   string
	HasPoint bool
	X, Y     float64
}

// eventLocationPayload is the subset of fields interest routing reads. Every
// ephemeral event that carries a position uses these names today; a payload
// missing them yields a zero EventLocation, which routing treats as
// unfiltered rather than as an error.
type eventLocationPayload struct {
	PageID string   `json:"pageId"`
	X      *float64 `json:"x"`
	Y      *float64 `json:"y"`
}

// LocationOf reads an event's page and point from its raw payload.
func LocationOf(payload json.RawMessage) EventLocation {
	var parsed eventLocationPayload
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return EventLocation{}
	}
	if parsed.X == nil || parsed.Y == nil {
		return EventLocation{PageID: parsed.PageID}
	}
	return EventLocation{PageID: parsed.PageID, HasPoint: true, X: *parsed.X, Y: *parsed.Y}
}

// InterestIndex tracks every connection's reported viewport and answers "who
// should hear about this event", so a room of hundreds does not mean every
// stroke reaches hundreds of sockets.
type InterestIndex interface {
	// Update replaces a connection's interest wholesale — there is no partial
	// update, because a stale page from a previous report combined with a
	// fresh viewport would describe a place nobody is actually looking at.
	Update(interest Interest)

	// Remove drops a connection's interest, on disconnect or on an interest
	// update that could not be parsed. A connection with no reported interest
	// is treated as interested in everything on its note — see Interested —
	// so this is safe to call speculatively.
	Remove(connectionID string)

	// Interested reports whether a connection cares about an event at the
	// given location.
	//
	// A connection this index has never heard from — no interest reported yet
	// — or an event with no location to filter by both count as interested in
	// everything. Filtering is an optimisation layered on top of correct
	// delivery, never a replacement for it: a client that has not yet reported
	// a viewport must not have its traffic silently dropped, or the room would
	// look broken during the first second after every join.
	Interested(connectionID string, location EventLocation) bool

	// RemoveNote drops every connection's interest for a note, once its room
	// has emptied — nothing keeps caring about page 3 of a canvas nobody has
	// open any more.
	RemoveNote(noteID string)

	Count() int
}
