package infrastructure

import (
	"sync"

	"mypol/go-realtime/internal/domain"
)

// MemoryRoomStore groups live connections by note.
//
// A room is not a persisted thing — it is exactly "who is connected to this
// note right now", which is per-instance by definition. Phase 1 runs a single
// instance; the port is what lets a Redis-backed directory replace this later
// without the relay layer changing.
//
// Rooms are deleted the moment they empty, so a server that has served a
// million notes holds only the ones currently open.
type MemoryRoomStore struct {
	mu    sync.RWMutex
	rooms map[string]map[string]domain.Connection // noteID -> connectionID -> conn
}

func NewMemoryRoomStore() *MemoryRoomStore {
	return &MemoryRoomStore{rooms: make(map[string]map[string]domain.Connection)}
}

// Join adds a connection to its note's room and reports the room size after.
func (s *MemoryRoomStore) Join(connection domain.Connection) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	noteID := connection.NoteID()
	room, ok := s.rooms[noteID]
	if !ok {
		room = make(map[string]domain.Connection)
		s.rooms[noteID] = room
	}
	room[connection.ID()] = connection
	return len(room)
}

// Leave removes a connection, dropping the room when it empties.
func (s *MemoryRoomStore) Leave(connection domain.Connection) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	noteID := connection.NoteID()
	room, ok := s.rooms[noteID]
	if !ok {
		return 0
	}

	delete(room, connection.ID())
	remaining := len(room)
	if remaining == 0 {
		delete(s.rooms, noteID)
	}
	return remaining
}

// Peers returns everyone in a note's room except the given connection.
//
// Returns a snapshot slice rather than holding the lock during fan-out: sending
// can block on a slow socket, and holding a room-wide lock while that happens
// would stall every other member.
func (s *MemoryRoomStore) Peers(noteID, exceptConnectionID string) []domain.Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	room := s.rooms[noteID]
	peers := make([]domain.Connection, 0, len(room))
	for id, connection := range room {
		if id == exceptConnectionID {
			continue
		}
		peers = append(peers, connection)
	}
	return peers
}

// Members returns every connection in a room, including the caller.
func (s *MemoryRoomStore) Members(noteID string) []domain.Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	room := s.rooms[noteID]
	members := make([]domain.Connection, 0, len(room))
	for _, connection := range room {
		members = append(members, connection)
	}
	return members
}

// ConnectionsForSession finds every connection bound to a session, so a revoked
// session can be disconnected rather than merely forgotten.
func (s *MemoryRoomStore) ConnectionsForSession(sessionID string) []domain.Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []domain.Connection
	for _, room := range s.rooms {
		for _, connection := range room {
			if connection.SessionID() == sessionID {
				matches = append(matches, connection)
			}
		}
	}
	return matches
}

// ConnectionsForUserOnNote finds a user's connections on one note, across tabs.
func (s *MemoryRoomStore) ConnectionsForUserOnNote(noteID, userID string) []domain.Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []domain.Connection
	for _, connection := range s.rooms[noteID] {
		if connection.UserID() == userID {
			matches = append(matches, connection)
		}
	}
	return matches
}

func (s *MemoryRoomStore) RoomCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rooms)
}

func (s *MemoryRoomStore) ConnectionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := 0
	for _, room := range s.rooms {
		total += len(room)
	}
	return total
}
