package application

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"mypol/go-realtime/internal/domain"
)

// HistoryPreviewPermit is installed only by the authenticated .NET control
// channel. The client supplies a reference, never the inverse's entity data.
type HistoryPreviewPermit struct {
	ID        string          `json:"permitId"`
	NoteID    string          `json:"noteId"`
	UserID    string          `json:"userId"`
	ExpiresAt int64           `json:"expiresAt"`
	Payload   json.RawMessage `json:"payload"`
}

type HistoryPreviews struct {
	mu      sync.Mutex
	permits map[string]HistoryPreviewPermit
}

func (p *HistoryPreviews) Register(permit HistoryPreviewPermit, now time.Time) error {
	if permit.ID == "" || permit.NoteID == "" || permit.UserID == "" || len(permit.Payload) > 48*1024 ||
		!json.Valid(permit.Payload) || permit.ExpiresAt <= now.UnixMilli() || permit.ExpiresAt > now.Add(30*time.Second).UnixMilli() {
		return errors.New("invalid history preview permit")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.permits == nil {
		p.permits = make(map[string]HistoryPreviewPermit)
	}
	for id, item := range p.permits {
		if item.ExpiresAt <= now.UnixMilli() {
			delete(p.permits, id)
		}
	}
	if len(p.permits) >= 1024 {
		return errors.New("history preview capacity reached")
	}
	if _, exists := p.permits[permit.ID]; exists {
		return errors.New("history preview permit already exists")
	}
	permit.Payload = append(json.RawMessage(nil), permit.Payload...)
	p.permits[permit.ID] = permit
	return nil
}

func (p *HistoryPreviews) Revoke(noteID, userID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, item := range p.permits {
		if item.NoteID == noteID && (userID == "" || item.UserID == userID) {
			delete(p.permits, id)
		}
	}
}

func (p *HistoryPreviews) Resolve(connection domain.Connection, raw json.RawMessage, now time.Time) (json.RawMessage, bool) {
	var request struct {
		PermitID  string `json:"permitId"`
		RequestID string `json:"requestId"`
		Ordinal   uint64 `json:"ordinal"`
	}
	if len(raw) > 1024 || json.Unmarshal(raw, &request) != nil || request.PermitID == "" || request.RequestID == "" || len(request.RequestID) > 64 || request.Ordinal == 0 {
		return nil, false
	}
	if connection.Permission() != domain.PermissionEdit && connection.Permission() != domain.PermissionOwner {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	permit, ok := p.permits[request.PermitID]
	if !ok || permit.NoteID != connection.NoteID() || permit.UserID != connection.UserID() || permit.ExpiresAt <= now.UnixMilli() {
		return nil, false
	}
	payload, err := json.Marshal(struct {
		Version   int             `json:"version"`
		RequestID string          `json:"requestId"`
		Ordinal   uint64          `json:"ordinal"`
		ExpiresAt int64           `json:"expiresAt"`
		Preview   json.RawMessage `json:"preview"`
	}{1, request.RequestID, request.Ordinal, permit.ExpiresAt, permit.Payload})
	return payload, err == nil
}
