package application

import (
	"errors"
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/infrastructure"
	"mypol/go-realtime/internal/security"
	"mypol/go-realtime/internal/testsupport"
)

type fixture struct {
	service  *SessionService
	keys     *testsupport.KeyPair
	sessions *infrastructure.MemorySessionStore
	tickets  *infrastructure.MemoryTicketStore
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	keys, err := testsupport.NewKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	validator, err := security.NewCanvasJWTValidator(
		keys.PublicPEM, testsupport.Issuer, testsupport.Audience, 0)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	now := time.Now()
	sessions := infrastructure.NewMemorySessionStore()
	tickets := infrastructure.NewMemoryTicketStore()

	return &fixture{
		service:  NewSessionService(sessions, tickets, validator, 30*time.Second, func() time.Time { return now }),
		keys:     keys,
		sessions: sessions,
		tickets:  tickets,
		now:      now,
	}
}

func (f *fixture) token(t *testing.T, in testsupport.ClaimsInput) string {
	t.Helper()
	signed, err := f.keys.Sign(testsupport.Claims(in))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestBootstrapCreatesSessionAndTicket(t *testing.T) {
	f := newFixture(t)

	result, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// The session id comes from the token's sid claim, so .NET can revoke a
	// session it authorised without asking Go what id it chose.
	if result.Session.ID != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("session id = %q", result.Session.ID)
	}
	if result.Session.Permission != domain.PermissionEdit {
		t.Errorf("permission = %q", result.Session.Permission)
	}
	if result.Ticket.Value == "" {
		t.Error("expected a connection ticket")
	}
	if !result.TicketExpiresAt.Equal(f.now.Add(30 * time.Second)) {
		t.Errorf("ticket expiry = %v, want +30s", result.TicketExpiresAt)
	}

	if _, ok := f.sessions.Get(result.Session.ID); !ok {
		t.Error("session should be stored")
	}
	if f.tickets.Count() != 1 {
		t.Errorf("ticket count = %d, want 1", f.tickets.Count())
	}
}

func TestBootstrapRejectsInvalidToken(t *testing.T) {
	f := newFixture(t)

	if _, err := f.service.Bootstrap("not-a-token"); !errors.Is(err, ErrSessionRejected) {
		t.Fatalf("expected ErrSessionRejected, got %v", err)
	}
	if f.sessions.Count() != 0 || f.tickets.Count() != 0 {
		t.Error("a rejected bootstrap must not leave state behind")
	}
}

func TestBootstrapCarriesPermissionOntoTicket(t *testing.T) {
	f := newFixture(t)

	result, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{Permission: "view"}))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// The ticket snapshots authorisation so the connect handler can bind a
	// connection without a second lookup.
	if result.Ticket.Permission != domain.PermissionView {
		t.Errorf("ticket permission = %q, want view", result.Ticket.Permission)
	}
	if result.Ticket.NoteID != result.Session.NoteID {
		t.Error("ticket and session must agree on the note")
	}
}

func TestTicketFromBootstrapIsSingleUse(t *testing.T) {
	f := newFixture(t)
	result, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if _, err := f.service.ConsumeTicket(result.Ticket.Value); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := f.service.ConsumeTicket(result.Ticket.Value); err == nil {
		t.Fatal("expected the second consume to fail")
	}
}

func TestBootstrapIssuesADistinctTicketEachTime(t *testing.T) {
	f := newFixture(t)

	first, _ := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))
	second, _ := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))

	if first.Ticket.Value == second.Ticket.Value {
		t.Fatal("each bootstrap must mint a fresh ticket")
	}
}

func TestRevokeSessionAlsoInvalidatesOutstandingTickets(t *testing.T) {
	f := newFixture(t)
	result, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	revoked, err := f.service.RevokeSession(result.Session.ID)
	if err != nil || !revoked {
		t.Fatalf("revoke = %v, %v", revoked, err)
	}

	// Otherwise a ticket minted moments before revocation could still be
	// redeemed against a session that no longer exists.
	if _, err := f.service.ConsumeTicket(result.Ticket.Value); err == nil {
		t.Fatal("tickets for a revoked session must not be redeemable")
	}
	if _, ok := f.sessions.Get(result.Session.ID); ok {
		t.Error("session should be gone")
	}
}

func TestRevokeUserFromNoteEndsEverySession(t *testing.T) {
	f := newFixture(t)

	for _, sid := range []string{"sid-a", "sid-b"} {
		if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
			UserID: "user-1", NoteID: "note-1", SessionID: sid,
		})); err != nil {
			t.Fatalf("bootstrap %s: %v", sid, err)
		}
	}
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
		UserID: "user-2", NoteID: "note-1", SessionID: "sid-other",
	})); err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}

	removed, err := f.service.RevokeUserFromNote("note-1", "user-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, ok := f.sessions.Get("sid-other"); !ok {
		t.Error("another user's session must survive")
	}
}

func TestUpdateSessionPermissionInPlace(t *testing.T) {
	f := newFixture(t)
	result, _ := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))

	if err := f.service.UpdateSessionPermission(result.Session.ID, domain.PermissionView); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Demotion must not end the session — the connection stays up.
	session, ok := f.service.Session(result.Session.ID)
	if !ok {
		t.Fatal("session should still exist after a permission change")
	}
	if session.Permission != domain.PermissionView {
		t.Errorf("permission = %q, want view", session.Permission)
	}
}

func TestUpdateSessionPermissionRejectsUnknownValue(t *testing.T) {
	f := newFixture(t)
	result, _ := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{}))

	if err := f.service.UpdateSessionPermission(result.Session.ID, domain.Permission("root")); !errors.Is(err, domain.ErrInvalidPermission) {
		t.Fatalf("expected ErrInvalidPermission, got %v", err)
	}
}

func TestSweepTicketsRemovesExpired(t *testing.T) {
	keys, err := testsupport.NewKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	validator, err := security.NewCanvasJWTValidator(keys.PublicPEM, testsupport.Issuer, testsupport.Audience, 0)
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	now := time.Now()
	clock := func() time.Time { return now }
	tickets := infrastructure.NewMemoryTicketStore()
	service := NewSessionService(infrastructure.NewMemorySessionStore(), tickets, validator, 30*time.Second, clock)

	token, _ := keys.Sign(testsupport.Claims(testsupport.ClaimsInput{IssuedAt: now}))
	if _, err := service.Bootstrap(token); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if swept := service.SweepTickets(); swept != 0 {
		t.Errorf("nothing should be swept yet, got %d", swept)
	}

	now = now.Add(31 * time.Second)
	if swept := service.SweepTickets(); swept != 1 {
		t.Errorf("swept = %d, want 1", swept)
	}
	if tickets.Count() != 0 {
		t.Errorf("count = %d, want 0", tickets.Count())
	}
}
