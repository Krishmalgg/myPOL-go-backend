package infrastructure

import (
	"sync"

	"mypol/go-realtime/internal/domain"
)

// MemoryInterestIndex maps connections to the grid cells they currently care
// about.
//
// Two directions are kept in step: connectionID -> its interest (to answer
// "what does this connection want", needed on removal and re-report) and
// cell -> connection ids (to answer "who is interested in this cell" in O(1)
// rather than scanning every connection on every event). Keeping only one and
// deriving the other would make either Update or Interested linear in the
// size of the room, and a room is exactly where that stops being cheap.
type MemoryInterestIndex struct {
	mu sync.RWMutex

	byConnection map[string]domain.Interest
	// byCell[noteID][pageID][cell] -> set of connection ids
	byCell map[string]map[string]map[domain.GridCell]map[string]struct{}
}

func NewMemoryInterestIndex() *MemoryInterestIndex {
	return &MemoryInterestIndex{
		byConnection: make(map[string]domain.Interest),
		byCell:       make(map[string]map[string]map[domain.GridCell]map[string]struct{}),
	}
}

func (idx *MemoryInterestIndex) Update(interest domain.Interest) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if existing, ok := idx.byConnection[interest.ConnectionID]; ok {
		idx.removeLocked(existing)
	}

	idx.byConnection[interest.ConnectionID] = interest
	for _, cell := range interest.Cells() {
		idx.addToCellLocked(interest.NoteID, interest.PageID, cell, interest.ConnectionID)
	}
}

func (idx *MemoryInterestIndex) Remove(connectionID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	existing, ok := idx.byConnection[connectionID]
	if !ok {
		return
	}
	idx.removeLocked(existing)
	delete(idx.byConnection, connectionID)
}

// Interested answers whether the given connection's own reported viewport
// covers the event's cell.
//
// The cell index exists to make this cheap — O(1) membership in the one
// cell's connection set — rather than to answer a different question. It is
// tempting to read "does *anyone* occupy this cell" off `byCell` directly, but
// that answers who is nearby in general, not whether *this* connection is:
// the set at a cell holds every connection watching it, and checking only
// that the set is non-empty would tell a viewer in a completely different
// corner of the page that a neighbour's cell entry makes it interested too.
func (idx *MemoryInterestIndex) Interested(connectionID string, location domain.EventLocation) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	interest, hasInterest := idx.byConnection[connectionID]
	if !hasInterest {
		// Nothing reported yet — degrade to "wants everything" rather than
		// silently dropping a brand new connection's traffic.
		return true
	}
	if !location.HasPoint {
		// No spatial claim to test against (e.g. an ink.points continuation),
		// so fall back to the page the event named, if any.
		return location.PageID == "" || location.PageID == interest.PageID
	}
	if location.PageID != "" && location.PageID != interest.PageID {
		return false
	}

	cell := domain.GridCell{
		X: int(location.X) / domain.GridCellSize,
		Y: int(location.Y) / domain.GridCellSize,
	}
	connections := idx.byCell[interest.NoteID][interest.PageID][cell]
	_, present := connections[connectionID]
	return present
}

// AllowsPreview reads the recipient preference without changing the spatial
// routing guarantee. A newly joined or older client has no index entry and is
// therefore allowed every preview until it explicitly says otherwise.
func (idx *MemoryInterestIndex) AllowsPreview(connectionID, event string) bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	interest, ok := idx.byConnection[connectionID]
	if !ok {
		return true
	}
	return interest.AllowsPreview(event)
}

func (idx *MemoryInterestIndex) RemoveNote(noteID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	delete(idx.byCell, noteID)
	for connectionID, interest := range idx.byConnection {
		if interest.NoteID == noteID {
			delete(idx.byConnection, connectionID)
		}
	}
}

func (idx *MemoryInterestIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.byConnection)
}

// ── internals, all called with the mutex held ───────────────────────────────

func (idx *MemoryInterestIndex) removeLocked(interest domain.Interest) {
	pages := idx.byCell[interest.NoteID]
	if pages == nil {
		return
	}
	cells := pages[interest.PageID]
	if cells == nil {
		return
	}
	for _, cell := range interest.Cells() {
		connections := cells[cell]
		if connections == nil {
			continue
		}
		delete(connections, interest.ConnectionID)
		if len(connections) == 0 {
			delete(cells, cell)
		}
	}
	if len(cells) == 0 {
		delete(pages, interest.PageID)
	}
	if len(pages) == 0 {
		delete(idx.byCell, interest.NoteID)
	}
}

func (idx *MemoryInterestIndex) addToCellLocked(
	noteID, pageID string,
	cell domain.GridCell,
	connectionID string,
) {
	pages, ok := idx.byCell[noteID]
	if !ok {
		pages = make(map[string]map[domain.GridCell]map[string]struct{})
		idx.byCell[noteID] = pages
	}
	cells, ok := pages[pageID]
	if !ok {
		cells = make(map[domain.GridCell]map[string]struct{})
		pages[pageID] = cells
	}
	connections, ok := cells[cell]
	if !ok {
		connections = make(map[string]struct{})
		cells[cell] = connections
	}
	connections[connectionID] = struct{}{}
}
