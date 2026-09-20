package domain

import (
	"encoding/json"
	"strings"
)

// EnvelopeVersion is the wire format this service speaks.
const EnvelopeVersion = 2

// Envelope is the shape every realtime message takes on the wire. It mirrors
// the frontend's envelope v2 exactly.
//
// Payload stays as raw JSON: the relay never needs to look inside it, and
// re-serialising would burn CPU on every fan-out while risking drift between
// what the sender wrote and what recipients receive.
type Envelope struct {
	V         int             `json:"v"`
	MessageID string          `json:"messageId"`
	SessionID string          `json:"sessionId"`
	Channel   string          `json:"channel"`
	Event     string          `json:"event"`
	ActorID   *string         `json:"actorId"`
	Origin    *string         `json:"origin"`
	Seq       *uint64         `json:"seq,omitempty"`
	SentAt    int64           `json:"sentAt"`
	Payload   json.RawMessage `json:"payload"`
}

// Stamp overwrites the fields a client must never be trusted to set.
//
// A client can claim to be anyone in the envelope it sends, so identity is
// taken from the authenticated connection instead and written over whatever
// arrived. Without this, one user could forge cursors and ink as another.
func (e *Envelope) Stamp(sessionID, connectionID, userID string, sentAt int64) {
	e.V = EnvelopeVersion
	e.SessionID = sessionID
	e.Origin = &connectionID
	e.ActorID = &userID
	e.SentAt = sentAt
}

// EventClass decides how a message may be delivered and which rate-limit
// bucket it draws from.
type EventClass int

const (
	// ClassEphemeral is live preview traffic: droppable, coalescable.
	ClassEphemeral EventClass = iota
	// ClassReliable is final state and control that must not be dropped.
	ClassReliable
	// ClassSignaling is WebRTC negotiation, metered separately because its
	// natural rate is far lower than canvas traffic.
	ClassSignaling
	// ClassDurable announces persisted state. Only .NET may emit these, so a
	// client sending one is rejected outright.
	ClassDurable
)

var ephemeralEvents = map[string]struct{}{
	"cursor.moved":                {},
	"laser.moved":                 {},
	"ink.started":                 {},
	"ink.points":                  {},
	"block.transform.preview":     {},
	"selection.transform.preview": {},
}

var signalingEvents = map[string]struct{}{
	"rtc.offer":     {},
	"rtc.answer":    {},
	"rtc.candidate": {},
}

var reliableEvents = map[string]struct{}{
	"ink.commit":             {},
	"ink.patch":              {},
	"ink.ended":              {},
	"block.transform.commit": {},
	"block.lock.request":     {},
	"block.lock.renew":       {},
	"block.lock.release":     {},
	"block.created":          {},
	"block.status":           {},
	"auth.refresh":           {},
	"server.draining":        {},
	"interest.update":        {},
	"yjs.update":             {},
}

// durablePrefixes are announcements from .NET about persisted state.
var durablePrefixes = []string{"note.", "collection.", "media.", "session.changed", "block.received", "block.broadcast"}

// ClassifyEvent maps an event name onto its traffic class.
func ClassifyEvent(event string) EventClass {
	if _, ok := ephemeralEvents[event]; ok {
		return ClassEphemeral
	}
	if _, ok := signalingEvents[event]; ok {
		return ClassSignaling
	}
	if _, ok := reliableEvents[event]; ok {
		return ClassReliable
	}
	for _, prefix := range durablePrefixes {
		if strings.HasPrefix(event, prefix) {
			return ClassDurable
		}
	}
	// Presence is server-authoritative here, so a client claiming one is not
	// relayable either — see MayPublish.
	if strings.HasPrefix(event, "presence.") || event == "room.members" {
		return ClassDurable
	}
	// Unknown events are treated as reliable: delivering something unnecessary
	// is recoverable, silently dropping final state is not.
	return ClassReliable
}

// MayPublish reports whether a permission level may send this event.
//
// Viewers and commenters are present on a canvas and may show a cursor, but
// must not be able to change it. Enforced here rather than trusting the client
// to hide its own toolbar.
func (p Permission) MayPublish(event string) bool {
	// Lifecycle control is server-authored. It is reliable so existing clients
	// can consume it as control JSON, but no client may impersonate a drain.
	if event == "server.draining" {
		return false
	}
	switch ClassifyEvent(event) {
	case ClassDurable:
		// Never client-relayable, whatever the permission.
		return false
	case ClassEphemeral:
		if event == "ink.started" || event == "ink.points" ||
			event == "block.transform.preview" || event == "selection.transform.preview" {
			return p.CanDraw()
		}
		return true
	case ClassSignaling:
		return true
	default:
		if strings.HasPrefix(event, "ink.") || strings.HasPrefix(event, "block.") {
			return p.CanDraw()
		}
		return true
	}
}
