package infrastructure

import (
	"sync"
	"time"

	"mypol/go-realtime/internal/domain"
)

// MemoryTicketStore holds unredeemed connection tickets.
//
// A plain mutex rather than RWMutex: the dominant operation is Consume, which
// writes, so a read/write split would add contention without buying anything.
type MemoryTicketStore struct {
	mu      sync.Mutex
	tickets map[string]*domain.ConnectionTicket
}

func NewMemoryTicketStore() *MemoryTicketStore {
	return &MemoryTicketStore{tickets: make(map[string]*domain.ConnectionTicket)}
}

func (s *MemoryTicketStore) Issue(ticket *domain.ConnectionTicket) error {
	if ticket == nil || ticket.Value == "" {
		return domain.ErrTicketNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickets[ticket.Value] = ticket.Clone()
	return nil
}

// Consume redeems a ticket and removes it in the same critical section.
//
// The delete has to happen under the same lock as the lookup, or two
// connections racing on one ticket could both be admitted — which would defeat
// the entire point of it being single-use. An expired ticket is deleted too:
// it is spent either way, and leaving it would let a caller distinguish
// "expired" from "never existed" by timing repeated attempts.
func (s *MemoryTicketStore) Consume(value string, now time.Time) (*domain.ConnectionTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ticket, ok := s.tickets[value]
	if !ok {
		return nil, domain.ErrTicketNotFound
	}

	delete(s.tickets, value)

	if ticket.IsExpired(now) {
		return nil, domain.ErrTicketExpired
	}
	return ticket.Clone(), nil
}

// SweepExpired drops tickets nobody redeemed, so an abandoned bootstrap cannot
// leak memory.
func (s *MemoryTicketStore) SweepExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for value, ticket := range s.tickets {
		if ticket.IsExpired(now) {
			delete(s.tickets, value)
			removed++
		}
	}
	return removed
}

// DeleteBySession revokes outstanding tickets when their session ends, so a
// revoked session cannot still be connected to with a ticket issued moments
// earlier.
func (s *MemoryTicketStore) DeleteBySession(sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for value, ticket := range s.tickets {
		if ticket.SessionID == sessionID {
			delete(s.tickets, value)
			removed++
		}
	}
	return removed
}

func (s *MemoryTicketStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}
