package domain

import (
	"encoding/json"
	"testing"
)

func TestCellsCoverTheReportedRectangleWithAMarginOfSlack(t *testing.T) {
	interest := Interest{PageID: "page-1", X: 0, Y: 0, Width: 100, Height: 100}
	cells := interest.Cells()

	// A 100x100 rectangle at the origin sits entirely inside cell (0,0), so
	// with one cell of margin on every side the result is the 3x3 block
	// around it.
	want := map[GridCell]bool{}
	for x := -1; x <= 1; x++ {
		for y := -1; y <= 1; y++ {
			want[GridCell{X: x, Y: y}] = true
		}
	}
	if len(cells) != len(want) {
		t.Fatalf("got %d cells, want %d", len(cells), len(want))
	}
	for _, cell := range cells {
		if !want[cell] {
			t.Errorf("unexpected cell %+v", cell)
		}
	}
}

// The margin is what absorbs the lag between an interest report and the pan
// that has happened since it was sent — without it, a viewport's leading edge
// would go dark until the next coalesced update landed.
func TestCellsIncludeOneCellOfMarginBeyondTheRectangle(t *testing.T) {
	interest := Interest{PageID: "p", X: 0, Y: 0, Width: 10, Height: 10}
	cells := interest.Cells()

	found := false
	for _, cell := range cells {
		if cell == (GridCell{X: -1, Y: -1}) {
			found = true
		}
	}
	if !found {
		t.Error("expected the margin cell (-1,-1) to be included")
	}
}

func TestCellsIsEmptyForANonPositiveRectangle(t *testing.T) {
	for _, interest := range []Interest{
		{PageID: "p", Width: 0, Height: 100},
		{PageID: "p", Width: 100, Height: 0},
		{PageID: "p", Width: -10, Height: 100},
	} {
		if cells := interest.Cells(); cells != nil {
			t.Errorf("Cells() = %v, want nil for a degenerate rectangle", cells)
		}
	}
}

// A viewport spanning two grid cells must produce both, or an event in the
// second half of the rectangle would be filtered out despite being visible.
func TestCellsSpanMultipleCellsForALargeViewport(t *testing.T) {
	interest := Interest{PageID: "p", X: 0, Y: 0, Width: GridCellSize * 3, Height: GridCellSize}
	cells := interest.Cells()

	spanX := map[int]bool{}
	for _, cell := range cells {
		spanX[cell.X] = true
	}
	// Cells 0, 1, 2 for the rectangle itself, plus -1 and 3 for the margin.
	for _, x := range []int{-1, 0, 1, 2, 3} {
		if !spanX[x] {
			t.Errorf("expected column %d to be covered", x)
		}
	}
}

func TestLocationOfReadsPageAndPoint(t *testing.T) {
	location := LocationOf(json.RawMessage(`{"pageId":"page-1","x":10,"y":20}`))
	if location.PageID != "page-1" || !location.HasPoint || location.X != 10 || location.Y != 20 {
		t.Errorf("LocationOf = %+v", location)
	}
}

// ink.points continuations carry only a stroke id, no position — the router
// must recognise this as "no point" rather than defaulting to (0,0), which
// would silently misroute every continuation to whoever is at the origin.
func TestLocationOfHasNoPointWhenCoordinatesAreAbsent(t *testing.T) {
	location := LocationOf(json.RawMessage(`{"strokeId":"s1"}`))
	if location.HasPoint {
		t.Error("expected HasPoint to be false when x/y are absent")
	}
}

func TestLocationOfSurvivesMalformedPayload(t *testing.T) {
	location := LocationOf(json.RawMessage(`not json`))
	if location.HasPoint || location.PageID != "" {
		t.Errorf("LocationOf(malformed) = %+v, want the zero value", location)
	}
}

func TestLocationOfIgnoresAPartialPoint(t *testing.T) {
	// Only one coordinate present is not a point either.
	location := LocationOf(json.RawMessage(`{"pageId":"p","x":10}`))
	if location.HasPoint {
		t.Error("expected HasPoint to be false when only one coordinate is present")
	}
}
