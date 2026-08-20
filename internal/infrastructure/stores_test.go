package infrastructure

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"mypol/go-realtime/internal/domain"
)

func newSession(id, userID, noteID string, expiresAt, lastSeen time.Time) *domain.CanvasSession {
	return &domain.CanvasSession{
		ID:         id,
		UserID:     userID,
		NoteID:     noteID,
		Permission: domain.PermissionEdit,
		TokenJTI:   "jti-" + id,
		ExpiresAt:  expiresAt,
		LastSeenAt: lastSeen,
		CreatedAt:  lastSeen,
	}
}

// ── session store ───────────────────────────────────────────────────────────

func TestSessionStoreSaveAndGet(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	session := newSession("s1", "u1", "n1", now.Add(time.Minute), now)

	if err := store.Save(session); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, ok := store.Get("s1")
	if !ok {
		t.Fatal("expected the session to be found")
	}
	if got.UserID != "u1" || got.NoteID != "n1" {
		t.Errorf("unexpected session %+v", got)
	}

	if _, ok := store.Get("missing"); ok {
		t.Error("expected a miss for an unknown id")
	}
}

// Handing out the stored pointer would let a caller mutate shared state with no
// lock held.
func TestSessionStoreReturnsCopies(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	if err := store.Save(newSession("s1", "u1", "n1", now.Add(time.Minute), now)); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, _ := store.Get("s1")
	got.Permission = domain.PermissionOwner

	fresh, _ := store.Get("s1")
	if fresh.Permission != domain.PermissionEdit {
		t.Fatal("mutating a returned session must not affect stored state")
	}
}

func TestSessionStoreDelete(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	_ = store.Save(newSession("s1", "u1", "n1", now.Add(time.Minute), now))

	if !store.Delete("s1") {
		t.Error("expected delete to report removal")
	}
	if store.Delete("s1") {
		t.Error("expected a second delete to report nothing removed")
	}
	if store.Count() != 0 {
		t.Errorf("count = %d, want 0", store.Count())
	}
}

// Revoking a person must catch every tab and device they have open on that note
// — and nothing belonging to anyone else.
func TestSessionStoreDeleteByUserAndNote(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	expiry := now.Add(time.Minute)

	_ = store.Save(newSession("tab1", "u1", "n1", expiry, now))
	_ = store.Save(newSession("tab2", "u1", "n1", expiry, now))
	_ = store.Save(newSession("other-note", "u1", "n2", expiry, now))
	_ = store.Save(newSession("other-user", "u2", "n1", expiry, now))

	if removed := store.DeleteByUserAndNote("u1", "n1"); removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, ok := store.Get("other-note"); !ok {
		t.Error("a session on another note must survive")
	}
	if _, ok := store.Get("other-user"); !ok {
		t.Error("another user's session must survive")
	}
}

func TestSessionStoreUpdatePermission(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	_ = store.Save(newSession("s1", "u1", "n1", now.Add(time.Minute), now))

	if err := store.UpdatePermission("s1", domain.PermissionView); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := store.Get("s1")
	if got.Permission != domain.PermissionView {
		t.Errorf("permission = %q, want view", got.Permission)
	}

	if err := store.UpdatePermission("missing", domain.PermissionView); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionStoreTouchAndSweep(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	idle := 45 * time.Second

	// Valid token, recently seen.
	_ = store.Save(newSession("live", "u1", "n1", now.Add(time.Hour), now))
	// Valid token, but gone silent.
	_ = store.Save(newSession("silent", "u2", "n1", now.Add(time.Hour), now.Add(-2*time.Minute)))
	// Recently seen, but the token has lapsed.
	_ = store.Save(newSession("expired", "u3", "n1", now.Add(-time.Second), now))

	if removed := store.SweepExpired(now, idle); removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, ok := store.Get("live"); !ok {
		t.Error("a live session must survive the sweep")
	}

	if err := store.Touch("live", now.Add(time.Minute)); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err := store.Touch("missing", now); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

// ── ticket store ────────────────────────────────────────────────────────────

func newTicket(value, sessionID string, expiresAt time.Time) *domain.ConnectionTicket {
	return &domain.ConnectionTicket{
		Value:      value,
		SessionID:  sessionID,
		UserID:     "u1",
		NoteID:     "n1",
		Permission: domain.PermissionEdit,
		ExpiresAt:  expiresAt,
		CreatedAt:  expiresAt.Add(-30 * time.Second),
	}
}

// The whole point of a ticket is that it works exactly once.
func TestTicketStoreConsumeIsSingleUse(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()
	_ = store.Issue(newTicket("abc", "s1", now.Add(30*time.Second)))

	ticket, err := store.Consume("abc", now)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if ticket.SessionID != "s1" || ticket.Permission != domain.PermissionEdit {
		t.Errorf("unexpected ticket %+v", ticket)
	}

	if _, err := store.Consume("abc", now); !errors.Is(err, domain.ErrTicketNotFound) {
		t.Fatalf("expected the second consume to fail, got %v", err)
	}
}

// Under a race only one caller may win, or two connections could be admitted on
// one ticket.
func TestTicketStoreConsumeIsRaceSafe(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()
	_ = store.Issue(newTicket("abc", "s1", now.Add(30*time.Second)))

	const racers = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0

	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			if _, err := store.Consume("abc", now); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("exactly one consumer must win, got %d", wins)
	}
}

func TestTicketStoreRejectsExpiredTicket(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()
	_ = store.Issue(newTicket("stale", "s1", now.Add(-time.Second)))

	if _, err := store.Consume("stale", now); !errors.Is(err, domain.ErrTicketExpired) {
		t.Fatalf("expected ErrTicketExpired, got %v", err)
	}
	// Spent either way: a retry must not be able to distinguish the two cases.
	if store.Count() != 0 {
		t.Error("an expired ticket should be removed on consume")
	}
}

func TestTicketStoreSweepExpired(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()
	_ = store.Issue(newTicket("fresh", "s1", now.Add(30*time.Second)))
	_ = store.Issue(newTicket("stale1", "s1", now.Add(-time.Second)))
	_ = store.Issue(newTicket("stale2", "s2", now.Add(-time.Minute)))

	if removed := store.SweepExpired(now); removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if store.Count() != 1 {
		t.Errorf("count = %d, want 1", store.Count())
	}
}

// A revoked session must not leave a redeemable ticket behind.
func TestTicketStoreDeleteBySession(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()
	_ = store.Issue(newTicket("a", "s1", now.Add(time.Minute)))
	_ = store.Issue(newTicket("b", "s1", now.Add(time.Minute)))
	_ = store.Issue(newTicket("c", "s2", now.Add(time.Minute)))

	if removed := store.DeleteBySession("s1"); removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, err := store.Consume("c", now); err != nil {
		t.Errorf("another session's ticket must survive: %v", err)
	}
}

func TestTicketStoreConcurrentIssueAndSweep(t *testing.T) {
	store := NewMemoryTicketStore()
	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = store.Issue(newTicket(fmt.Sprintf("t%d", i), "s1", now.Add(time.Minute)))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			store.SweepExpired(now)
		}
	}()
	wg.Wait()
}
