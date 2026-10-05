package transport

import (
	"encoding/json"
	"mypol/go-realtime/internal/application"
	"net/http"
)

func (h *Handlers) RegisterHistoryPreview(w http.ResponseWriter, r *http.Request) {
	body, ok := h.authenticateInternal(w, r)
	if !ok {
		return
	}
	var permit application.HistoryPreviewPermit
	if json.Unmarshal(body, &permit) != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "Invalid preview permit.")
		return
	}
	if err := h.rooms.HistoryPreviews.Register(permit, h.now()); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PREVIEW", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

func (h *Handlers) RevokeHistoryPreviews(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticateInternal(w, r); !ok {
		return
	}
	h.rooms.HistoryPreviews.Revoke(r.PathValue("noteId"), r.PathValue("userId"))
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}
