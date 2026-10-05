package application

import (
	"encoding/json"
	"mypol/go-realtime/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestHistoryPreviewPermitScopeExpiryAndPayload(t *testing.T) {
	now := time.Unix(100, 0)
	previews := &HistoryPreviews{}
	permit := HistoryPreviewPermit{ID: "permit", NoteID: "note", UserID: "alice", ExpiresAt: now.Add(time.Second).UnixMilli(), Payload: json.RawMessage(`{"entryId":"entry","redo":false}`)}
	if err := previews.Register(permit, now); err != nil {
		t.Fatal(err)
	}
	request := json.RawMessage(`{"permitId":"permit","requestId":"op","ordinal":1,"preview":{"forged":true}}`)
	alice := newFakeConnection("a", "s", "alice", "note")
	payload, ok := previews.Resolve(alice, request, now)
	if !ok || strings.Contains(string(payload), "forged") || !strings.Contains(string(payload), "entry") {
		t.Fatalf("unexpected payload: %s", payload)
	}
	bob := newFakeConnection("b", "s2", "bob", "note")
	if _, ok := previews.Resolve(bob, request, now); ok {
		t.Fatal("another actor used permit")
	}
	otherNote := newFakeConnection("c", "s3", "alice", "different")
	if _, ok := previews.Resolve(otherNote, request, now); ok {
		t.Fatal("cross-note permit accepted")
	}
	alice.SetPermission(domain.PermissionView)
	if _, ok := previews.Resolve(alice, request, now); ok {
		t.Fatal("viewer used permit")
	}
	alice.SetPermission(domain.PermissionEdit)
	if _, ok := previews.Resolve(alice, request, now.Add(time.Second)); ok {
		t.Fatal("expired permit accepted")
	}
	previews.Revoke("note", "alice")
	if _, ok := previews.Resolve(alice, request, now); ok {
		t.Fatal("revoked permit accepted")
	}
}

func TestHistoryPreviewRejectsUnboundedPermits(t *testing.T) {
	now := time.Now()
	previews := &HistoryPreviews{}
	permit := HistoryPreviewPermit{ID: "p", NoteID: "n", UserID: "u", ExpiresAt: now.Add(time.Minute).UnixMilli(), Payload: json.RawMessage(`{}`)}
	if err := previews.Register(permit, now); err == nil {
		t.Fatal("long-lived permit accepted")
	}
	permit.ExpiresAt = now.Add(time.Second).UnixMilli()
	if err := previews.Register(permit, now); err != nil {
		t.Fatal(err)
	}
	if err := previews.Register(permit, now); err == nil {
		t.Fatal("permit overwritten")
	}
}
