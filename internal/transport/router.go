package transport

import (
	"net/http"
)

// NewRouter wires the public and internal endpoints.
//
// Public and internal routes share a mux but not a trust model: everything
// under /internal/ is authenticated by HMAC inside its handler, and nothing
// under /v1/ can reach those paths.
func NewRouter(h *Handlers, allowedOrigins []string, websocket http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.Healthz)
	mux.HandleFunc("GET /readyz", h.Readyz)
	// Counts only — no session, note or user identifiers, since this endpoint
	// exists to be scraped.
	mux.HandleFunc("GET /metrics", h.Metrics().Handler())

	mux.HandleFunc("POST /v1/sessions/bootstrap", h.Bootstrap)

	if websocket != nil {
		// The ticket travels in the query string because a browser cannot set
		// headers on a WebSocket handshake. That is safe only because it is
		// single-use and expires in seconds.
		mux.HandleFunc("GET /ws", websocket)
	}

	mux.HandleFunc("POST /internal/v1/sessions/revoke", h.RevokeSession)
	mux.HandleFunc("POST /internal/v1/sessions/permission", h.UpdateSessionPermission)
	mux.HandleFunc("POST /internal/v1/notes/{noteId}/users/{userId}/revoke", h.RevokeUserFromNote)

	return withCORS(mux, allowedOrigins)
}

// withCORS allows the browser to call bootstrap cross-origin.
//
// The origin is echoed only when it is on the allow-list — reflecting an
// arbitrary Origin back would defeat the check entirely. Internal control paths
// are excluded: they are server-to-server and no browser should be able to
// preflight them.
func withCORS(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && isInternalPath(r.URL.Path) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if originAllowed(allowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
			// Responses differ by Origin, so caches must not share them.
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isInternalPath(path string) bool {
	const prefix = "/internal/"
	return len(path) >= len(prefix) && path[:len(prefix)] == prefix
}
