package infrastructure

import (
	"testing"

	"mypol/go-realtime/internal/domain"
)

func TestAConnectionWithNoReportedInterestIsInterestedInEverything(t *testing.T) {
	idx := NewMemoryInterestIndex()

	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 9999, Y: 9999}) {
		t.Error("a connection that has never reported a viewport must not be filtered")
	}
}

func TestAConnectionSeesEventsInsideItsReportedViewport(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 50, Y: 50}) {
		t.Error("an event inside the reported viewport should be delivered")
	}
}

// The whole point of the feature: someone looking at the far side of a large
// page must not receive a stroke happening nowhere near their viewport.
func TestAConnectionDoesNotSeeEventsFarOutsideItsViewport(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	far := domain.GridCellSize * 10
	if idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Error("an event far outside the viewport should not be delivered")
	}
}

func TestAConnectionOnADifferentPageDoesNotSeeTheEvent(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	if idx.Interested("conn-1", domain.EventLocation{PageID: "page-2", HasPoint: true, X: 10, Y: 10}) {
		t.Error("an event on a different page must not be delivered")
	}
}

// The margin exists precisely so a viewport that has panned slightly since its
// last report still receives what has newly come into view.
func TestTheMarginAbsorbsAPointJustOutsideTheReportedRectangle(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	// Just past the reported rectangle, but still within the first cell of
	// margin (cell size is 512, so 150 is still inside the margin cell).
	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 150, Y: 50}) {
		t.Error("a point just outside the viewport but within the margin should still be delivered")
	}
}

// A stroke continuation (ink.points) carries no point, only a page. Filtering
// must fall back to page-level rather than treating "no point" as "nowhere".
func TestAnEventWithNoPointFallsBackToPageLevelFiltering(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1"}) {
		t.Error("a same-page event with no point should still be delivered")
	}
	if idx.Interested("conn-1", domain.EventLocation{PageID: "page-2"}) {
		t.Error("a different-page event with no point should not be delivered")
	}
}

func TestUpdateReplacesRatherThanMerges(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})
	// Moves to page 2 entirely.
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-2",
		X: 0, Y: 0, Width: 100, Height: 100,
	})

	if idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 10, Y: 10}) {
		t.Error("the old page's interest should not linger after an update")
	}
	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-2", HasPoint: true, X: 10, Y: 10}) {
		t.Error("the new page's interest should be in effect")
	}
}

func TestRemoveClearsAConnectionsInterest(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})
	idx.Remove("conn-1")

	// Back to "nothing reported" — interested in everything again.
	far := domain.GridCellSize * 10
	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Error("removing interest should fall back to unfiltered, not to nothing")
	}
}

func TestRemoveOnAnUnknownConnectionIsANoop(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Remove("never-existed") // must not panic
	if idx.Count() != 0 {
		t.Errorf("Count() = %d, want 0", idx.Count())
	}
}

func TestCountReflectsLiveConnections(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{ConnectionID: "conn-1", NoteID: "note-1", PageID: "p", Width: 10, Height: 10})
	idx.Update(domain.Interest{ConnectionID: "conn-2", NoteID: "note-1", PageID: "p", Width: 10, Height: 10})
	if idx.Count() != 2 {
		t.Errorf("Count() = %d, want 2", idx.Count())
	}

	idx.Remove("conn-1")
	if idx.Count() != 1 {
		t.Errorf("Count() = %d, want 1 after removing one", idx.Count())
	}
}

// Two viewers on separate notes must never affect one another — a page id
// happening to repeat across notes is routine (every note starts at page 1).
func TestInterestOnOneNoteDoesNotLeakToAnother(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{
		ConnectionID: "conn-1", NoteID: "note-a", PageID: "page-1",
		X: 0, Y: 0, Width: 100, Height: 100,
	})
	idx.Update(domain.Interest{
		ConnectionID: "conn-2", NoteID: "note-b", PageID: "page-1",
		X: 9999, Y: 9999, Width: 10, Height: 10,
	})

	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 10, Y: 10}) {
		t.Error("conn-1 should see its own note's nearby event")
	}
}

func TestRemoveNoteDropsEveryConnectionOnIt(t *testing.T) {
	idx := NewMemoryInterestIndex()
	idx.Update(domain.Interest{ConnectionID: "conn-1", NoteID: "note-1", PageID: "p", Width: 10, Height: 10})
	idx.Update(domain.Interest{ConnectionID: "conn-2", NoteID: "note-2", PageID: "p", Width: 10, Height: 10})

	idx.RemoveNote("note-1")

	if idx.Count() != 1 {
		t.Errorf("Count() = %d, want 1 after removing note-1", idx.Count())
	}
	far := domain.GridCellSize * 10
	if !idx.Interested("conn-1", domain.EventLocation{PageID: "p", HasPoint: true, X: float64(far), Y: float64(far)}) {
		t.Error("conn-1's interest should be gone, falling back to unfiltered")
	}
}

// A connection that reacquires interest after moving away and back must not
// find a phantom membership left behind by an earlier report — the internal
// cell sets have to be fully unwound on every replace, not merely appended to.
func TestRepeatedUpdatesDoNotLeakStaleCellMemberships(t *testing.T) {
	idx := NewMemoryInterestIndex()
	far := domain.GridCellSize * 20

	for i := 0; i < 5; i++ {
		idx.Update(domain.Interest{
			ConnectionID: "conn-1", NoteID: "note-1", PageID: "page-1",
			X: float64(i * far), Y: 0, Width: 10, Height: 10,
		})
	}

	// Only the final position should still count as "interested".
	if !idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: float64(4 * far), Y: 0}) {
		t.Error("the most recent viewport should be in effect")
	}
	if idx.Interested("conn-1", domain.EventLocation{PageID: "page-1", HasPoint: true, X: 0, Y: 0}) {
		t.Error("an earlier viewport must not still match after later updates")
	}
}
