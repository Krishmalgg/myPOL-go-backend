package application

import (
	"errors"
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
	"mypol/go-realtime/internal/testsupport"
)

// A five-minute token must not mean a five-minute session: the client trades a
// fresh token over the connection it already holds, and the expiry moves forward
// without the socket closing.
func TestRefreshExtendsTheSessionInPlace(t *testing.T) {
	f := newFixture(t)
	original, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", IssuedAt: f.now, TTL: 5 * time.Minute,
	}))
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Issued now, but with a longer life: a token whose nbf is in the future is
	// not yet valid, which is exactly what a real refresh avoids.
	refreshed, err := f.service.RefreshSession("sid-1", f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", IssuedAt: f.now, TTL: 20 * time.Minute,
	}))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if !refreshed.ExpiresAt.After(original.Session.ExpiresAt) {
		t.Errorf("expiry did not move forward: %v -> %v",
			original.Session.ExpiresAt, refreshed.ExpiresAt)
	}
	if refreshed.ID != "sid-1" {
		t.Errorf("session id changed to %q", refreshed.ID)
	}
}

// A token for a different note would silently repoint a live connection at
// someone else's canvas.
func TestRefreshRejectsATokenForAnotherSession(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", NoteID: "note-1", UserID: "user-1",
	})); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	cases := map[string]testsupport.ClaimsInput{
		"different note":    {SessionID: "sid-1", NoteID: "note-2", UserID: "user-1"},
		"different user":    {SessionID: "sid-1", NoteID: "note-1", UserID: "user-2"},
		"different session": {SessionID: "sid-other", NoteID: "note-1", UserID: "user-1"},
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.service.RefreshSession("sid-1", f.token(t, claims)); err == nil {
				t.Fatal("expected the refresh to be rejected")
			}
		})
	}
}

func TestRefreshRejectsAnInvalidToken(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{SessionID: "sid-1"})); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if _, err := f.service.RefreshSession("sid-1", "not-a-token"); !errors.Is(err, ErrSessionRejected) {
		t.Fatalf("expected ErrSessionRejected, got %v", err)
	}
}

func TestRefreshRejectsAnUnknownSession(t *testing.T) {
	f := newFixture(t)

	_, err := f.service.RefreshSession("never-existed", f.token(t, testsupport.ClaimsInput{
		SessionID: "never-existed",
	}))
	if !errors.Is(err, domain.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// A demotion issued by .NET must take effect on the live session.
func TestRefreshAppliesADemotion(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", Permission: "edit",
	})); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	refreshed, err := f.service.RefreshSession("sid-1", f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", Permission: "view",
	}))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if refreshed.Permission != domain.PermissionView {
		t.Fatalf("permission = %q, want view", refreshed.Permission)
	}
}

// Escalation is a new session's job. Allowing it here would let a stale-but-
// valid higher-permission token be replayed to climb back up after a demotion.
func TestRefreshNeverEscalatesPermission(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", Permission: "view",
	})); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	refreshed, err := f.service.RefreshSession("sid-1", f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1", Permission: "owner",
	}))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if refreshed.Permission != domain.PermissionView {
		t.Fatalf("permission escalated to %q", refreshed.Permission)
	}
}

func TestRefreshKeepsTheSessionAlive(t *testing.T) {
	f := newFixture(t)
	if _, err := f.service.Bootstrap(f.token(t, testsupport.ClaimsInput{SessionID: "sid-1"})); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if _, err := f.service.RefreshSession("sid-1", f.token(t, testsupport.ClaimsInput{
		SessionID: "sid-1",
	})); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// The whole point: the session survives, so the transport does too.
	if _, ok := f.service.Session("sid-1"); !ok {
		t.Fatal("session should still exist after a refresh")
	}
}
