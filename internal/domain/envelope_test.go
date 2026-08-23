package domain

import "testing"

func TestClassifyEvent(t *testing.T) {
	cases := map[string]EventClass{
		"cursor.moved":            ClassEphemeral,
		"laser.moved":             ClassEphemeral,
		"ink.started":             ClassEphemeral,
		"ink.points":              ClassEphemeral,
		"block.transform.preview": ClassEphemeral,

		"ink.commit":             ClassReliable,
		"ink.ended":              ClassReliable,
		"block.transform.commit": ClassReliable,
		"block.created":          ClassReliable,
		"block.status":           ClassReliable,
		"auth.refresh":           ClassReliable,

		"rtc.offer":     ClassSignaling,
		"rtc.answer":    ClassSignaling,
		"rtc.candidate": ClassSignaling,

		"note.blocks.changed":      ClassDurable,
		"collection.notes.changed": ClassDurable,
		"media.ready":              ClassDurable,
		"presence.joined":          ClassDurable,
		"room.members":             ClassDurable,
	}

	for event, want := range cases {
		if got := ClassifyEvent(event); got != want {
			t.Errorf("ClassifyEvent(%q) = %v, want %v", event, got, want)
		}
	}
}

// Dropping something unknown could silently lose final state; delivering it
// unnecessarily is recoverable.
func TestUnknownEventsAreTreatedAsReliable(t *testing.T) {
	if ClassifyEvent("something.invented.later") != ClassReliable {
		t.Error("unknown events should default to reliable")
	}
}

func TestViewersMayBePresentButNotDraw(t *testing.T) {
	for _, permission := range []Permission{PermissionView, PermissionComment} {
		if !permission.MayPublish("cursor.moved") {
			t.Errorf("%s should be able to move a cursor", permission)
		}
		if permission.MayPublish("ink.started") {
			t.Errorf("%s must not be able to draw", permission)
		}
		if permission.MayPublish("ink.points") {
			t.Errorf("%s must not be able to stream ink", permission)
		}
		if permission.MayPublish("ink.commit") {
			t.Errorf("%s must not be able to commit a stroke", permission)
		}
		if permission.MayPublish("block.transform.commit") {
			t.Errorf("%s must not be able to move blocks", permission)
		}
		// A viewer may watch a media upload happen but must not be able to
		// announce one — that would let a read-only participant conjure a
		// block into a canvas they have no write access to.
		if permission.MayPublish("block.created") {
			t.Errorf("%s must not be able to announce a new block", permission)
		}
		if permission.MayPublish("block.status") {
			t.Errorf("%s must not be able to announce media progress", permission)
		}
	}
}

func TestEditorsMayDraw(t *testing.T) {
	for _, permission := range []Permission{PermissionEdit, PermissionOwner} {
		for _, event := range []string{
			"cursor.moved", "ink.started", "ink.points", "ink.commit",
			"block.created", "block.status",
		} {
			if !permission.MayPublish(event) {
				t.Errorf("%s should be allowed to publish %q", permission, event)
			}
		}
	}
}

// Only the server may claim something was persisted, or that someone joined.
func TestNobodyMayPublishServerOwnedEvents(t *testing.T) {
	for _, permission := range []Permission{PermissionView, PermissionEdit, PermissionOwner} {
		for _, event := range []string{
			"note.blocks.changed", "presence.joined", "presence.left", "room.members",
		} {
			if permission.MayPublish(event) {
				t.Errorf("%s must not be able to publish %q", permission, event)
			}
		}
	}
}

// A client can put anything in the envelope it sends, so identity is taken from
// the authenticated connection and written over whatever arrived.
func TestStampOverwritesClientClaimedIdentity(t *testing.T) {
	forged := "victim-connection"
	forgedUser := "victim-user"
	envelope := &Envelope{
		V:         99,
		SessionID: "forged-session",
		Origin:    &forged,
		ActorID:   &forgedUser,
		SentAt:    1,
	}

	envelope.Stamp("real-session", "real-connection", "real-user", 12345)

	if envelope.V != EnvelopeVersion {
		t.Errorf("V = %d", envelope.V)
	}
	if envelope.SessionID != "real-session" {
		t.Errorf("SessionID = %q", envelope.SessionID)
	}
	if *envelope.Origin != "real-connection" {
		t.Errorf("Origin = %q", *envelope.Origin)
	}
	if *envelope.ActorID != "real-user" {
		t.Errorf("ActorID = %q", *envelope.ActorID)
	}
	if envelope.SentAt != 12345 {
		t.Errorf("SentAt = %d", envelope.SentAt)
	}
}
