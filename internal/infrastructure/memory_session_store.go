package infrastructure

import (
	"sync"
	"time"

	"mypol/go-realtime/internal/domain"
)

// MemorySessionStore keeps live canvas sessions in process memory.
//
// Deliberate for phase 1: a session is a live thing tied to a connection this
// instance owns, so a restart legitimately ends all of them. Horizontal scaling
// swaps this for a shared store behind the same port without the application
// layer changing.
//
// Sessions are cloned on the way in and out. Handing out the stored pointer
// would let a caller mutate shared state with no lock held, which is the kind of
// race that only shows up under load.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*domain.CanvasSession
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*domain.CanvasSession)}
}

func (s *MemorySessionStore) Save(session *domain.CanvasSession) error {
	if session == nil || session.ID == "" {
		return domain.ErrSessionNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session.Clone()
	return nil
}

func (s *MemorySessionStore) Get(sessionID string) (*domain.CanvasSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	return session.Clone(), true
}

func (s *MemorySessionStore) Delete(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sessionID]; !ok {
		return false
	}
	delete(s.sessions, sessionID)
	return true
}

// DeleteByUserAndNote removes every session a user holds on a note. Scans
// rather than indexes: rooms are small and revocation is rare, so a second
// index would be complexity without measurable benefit.
func (s *MemorySessionStore) DeleteByUserAndNote(userID, noteID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, session := range s.sessions {
		if session.UserID == userID && session.NoteID == noteID {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

func (s *MemorySessionStore) UpdatePermission(sessionID string, permission domain.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.ErrSessionNotFound
	}
	session.Permission = permission
	return nil
}

func (s *MemorySessionStore) Touch(sessionID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return domain.ErrSessionNotFound
	}
	session.Touch(now)
	return nil
}

// SweepExpired drops sessions whose token lapsed or which have gone silent.
func (s *MemorySessionStore) SweepExpired(now time.Time, idleTimeout time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, session := range s.sessions {
		if session.IsExpired(now) || session.IsIdle(now, idleTimeout) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

func (s *MemorySessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
