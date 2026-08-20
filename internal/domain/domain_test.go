package domain

import (
	"errors"
	"testing"
	"time"
)

func TestParsePermissionAcceptsKnownValues(t *testing.T) {
	cases := map[string]Permission{
		"view":    PermissionView,
		"comment": PermissionComment,
		"edit":    PermissionEdit,
		"owner":   PermissionOwner,
	}
	for input, want := range cases {
		got, err := ParsePermission(input)
		if err != nil {
			t.Errorf("ParsePermission(%q) errored: %v", input, err)
		}
		if got != want {
			t.Errorf("ParsePermission(%q) = %q, want %q", input, got, want)
		}
	}
}

// An unrecognised permission must never be coerced into a usable one.
func TestParsePermissionRejectsUnknownValues(t *testing.T) {
	for _, input := range []string{"", "admin", "Edit", "root", "write"} {
		if _, err := ParsePermission(input); !errors.Is(err, ErrInvalidPermission) {
			t.Errorf("ParsePermission(%q) should have failed, got %v", input, err)
		}
	}
}

func TestOnlyEditAndOwnerMayDraw(t *testing.T) {
	if !PermissionEdit.CanDraw() || !PermissionOwner.CanDraw() {
		t.Error("edit and owner must be able to draw")
	}
	if PermissionView.CanDraw() || PermissionComment.CanDraw() {
		t.Error("view and comment must not be able to draw")
	}
}

func TestSessionExpiryIsInclusiveOfTheBoundary(t *testing.T) {
	now := time.Now()
	session := &CanvasSession{ExpiresAt: now}

	// At exactly the expiry instant the token is spent, not still valid.
	if !session.IsExpired(now) {
		t.Error("a session should be expired at its expiry instant")
	}
	if session.IsExpired(now.Add(-time.Second)) {
		t.Error("a session should be live before its expiry")
	}
}

func TestSessionIdleIsSeparateFromExpiry(t *testing.T) {
	now := time.Now()
	// A valid token can still belong to a client that has gone silent.
	session := &CanvasSession{
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now.Add(-time.Minute),
	}

	if session.IsExpired(now) {
		t.Error("token has not lapsed")
	}
	if !session.IsIdle(now, 45*time.Second) {
		t.Error("expected the session to be idle")
	}

	session.Touch(now)
	if session.IsIdle(now, 45*time.Second) {
		t.Error("touching should reset idleness")
	}
}

func TestTicketExpiry(t *testing.T) {
	now := time.Now()
	ticket := &ConnectionTicket{ExpiresAt: now.Add(30 * time.Second)}

	if ticket.IsExpired(now) {
		t.Error("ticket should still be valid")
	}
	if !ticket.IsExpired(now.Add(31 * time.Second)) {
		t.Error("ticket should have expired")
	}
}

func TestCloneIsolatesStoredState(t *testing.T) {
	session := &CanvasSession{ID: "s1", Permission: PermissionEdit}
	clone := session.Clone()
	clone.Permission = PermissionOwner
	if session.Permission != PermissionEdit {
		t.Error("session clone must not alias the original")
	}

	ticket := &ConnectionTicket{Value: "v", Permission: PermissionEdit}
	ticketClone := ticket.Clone()
	ticketClone.Permission = PermissionOwner
	if ticket.Permission != PermissionEdit {
		t.Error("ticket clone must not alias the original")
	}
}
