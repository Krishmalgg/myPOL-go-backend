package application

import (
	"errors"
	"fmt"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/security"
)

var ErrSessionRejected = errors.New("canvas session rejected")

// Clock is injected so tests can pin time instead of sleeping.
type Clock func() time.Time

// BootstrapResult is what a client needs to open a realtime connection.
type BootstrapResult struct {
	Session         *domain.CanvasSession
	Ticket          *domain.ConnectionTicket
	TicketExpiresAt time.Time
}

// SessionService turns a validated canvas token into a live session plus a
// one-time ticket.
//
// The split matters: the token proves *authorisation* and is comparatively long
// lived, while the ticket is a single-use *connection* credential safe to put in
// a URL. Trading one for the other at bootstrap is what keeps the JWT out of
// WebSocket query strings and therefore out of proxy logs.
type SessionService struct {
	sessions  domain.SessionStore
	tickets   domain.TicketStore
	validator *security.CanvasJWTValidator
	ticketTTL time.Duration
	now       Clock
}

func NewSessionService(
	sessions domain.SessionStore,
	tickets domain.TicketStore,
	validator *security.CanvasJWTValidator,
	ticketTTL time.Duration,
	now Clock,
) *SessionService {
	if now == nil {
		now = time.Now
	}
	return &SessionService{
		sessions:  sessions,
		tickets:   tickets,
		validator: validator,
		ticketTTL: ticketTTL,
		now:       now,
	}
}

// Bootstrap validates a canvas access token and establishes a session.
//
// The session id comes from the token's `sid` claim rather than being generated
// here, so .NET can revoke a session it authorised without first asking Go what
// id it chose.
func (s *SessionService) Bootstrap(token string) (*BootstrapResult, error) {
	claims, err := s.validator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionRejected, err)
	}

	now := s.now()
	session := &domain.CanvasSession{
		ID:         claims.SessionID,
		UserID:     claims.UserID,
		NoteID:     claims.NoteID,
		Permission: claims.Permission,
		TokenJTI:   claims.TokenID,
		ExpiresAt:  claims.ExpiresAt,
		LastSeenAt: now,
		CreatedAt:  now,
	}
	if err := s.sessions.Save(session); err != nil {
		return nil, err
	}

	ticket, err := s.issueTicket(session, now)
	if err != nil {
		return nil, err
	}

	return &BootstrapResult{
		Session:         session,
		Ticket:          ticket,
		TicketExpiresAt: ticket.ExpiresAt,
	}, nil
}

func (s *SessionService) issueTicket(session *domain.CanvasSession, now time.Time) (*domain.ConnectionTicket, error) {
	value, err := security.NewTicketValue()
	if err != nil {
		return nil, fmt.Errorf("could not generate connection ticket: %w", err)
	}

	// The ticket carries a snapshot of the authorisation so the connect handler
	// can bind a connection without a second lookup.
	ticket := &domain.ConnectionTicket{
		Value:      value,
		SessionID:  session.ID,
		UserID:     session.UserID,
		NoteID:     session.NoteID,
		Permission: session.Permission,
		ExpiresAt:  now.Add(s.ticketTTL),
		CreatedAt:  now,
	}
	if err := s.tickets.Issue(ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

// ConsumeTicket redeems a connection ticket. Single-use is enforced by the
// store, not here, because two connections can race for the same value.
func (s *SessionService) ConsumeTicket(value string) (*domain.ConnectionTicket, error) {
	return s.tickets.Consume(value, s.now())
}

// RevokeSession ends one session immediately and invalidates any ticket still
// outstanding for it — otherwise a ticket issued a moment earlier could still be
// redeemed against a session that no longer exists.
func (s *SessionService) RevokeSession(sessionID string) (bool, error) {
	if sessionID == "" {
		return false, domain.ErrSessionNotFound
	}
	s.tickets.DeleteBySession(sessionID)
	return s.sessions.Delete(sessionID), nil
}

// RevokeUserFromNote ends every session a user holds on a note, across tabs and
// devices, and returns how many were ended.
func (s *SessionService) RevokeUserFromNote(noteID, userID string) (int, error) {
	if noteID == "" || userID == "" {
		return 0, domain.ErrSessionNotFound
	}
	return s.sessions.DeleteByUserAndNote(userID, noteID), nil
}

// UpdateSessionPermission changes what a live session may do without ending it,
// so an editor can be demoted to a viewer without dropping their connection.
func (s *SessionService) UpdateSessionPermission(sessionID string, permission domain.Permission) error {
	if !permission.Valid() {
		return domain.ErrInvalidPermission
	}
	return s.sessions.UpdatePermission(sessionID, permission)
}

// SweepTickets drops unredeemed tickets past their TTL.
func (s *SessionService) SweepTickets() int {
	return s.tickets.SweepExpired(s.now())
}

// SweepSessions drops expired and idle sessions.
func (s *SessionService) SweepSessions(idleTimeout time.Duration) int {
	return s.sessions.SweepExpired(s.now(), idleTimeout)
}

// Session exposes a session for connection binding and tests.
func (s *SessionService) Session(sessionID string) (*domain.CanvasSession, bool) {
	return s.sessions.Get(sessionID)
}
