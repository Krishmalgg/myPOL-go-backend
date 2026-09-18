package transport

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"mypol/go-realtime/internal/config"
)

func handlersWithWebSocketURL(configured string) *Handlers {
	return &Handlers{cfg: &config.Config{WebSocketURL: configured}}
}

// A configured URL is authoritative: behind a proxy the public address cannot
// be recovered from the request, so the request must not be allowed to win.
func TestWebSocketURLPrefersConfiguration(t *testing.T) {
	h := handlersWithWebSocketURL("wss://realtime.example/ws")
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	req.Host = "192.168.1.129:8081"

	if got := h.websocketURL(req); got != "wss://realtime.example/ws" {
		t.Fatalf("websocketURL = %q, want the configured value", got)
	}
}

// Unconfigured, the client is sent back to the host it just reached. This is
// what lets a development machine change network without reconfiguration.
func TestWebSocketURLDerivesFromRequestHost(t *testing.T) {
	h := handlersWithWebSocketURL("")

	for _, host := range []string{
		"localhost:8081",
		"192.168.1.129:8081",
		"192.168.1.247:8081",
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
		req.Host = host

		want := "ws://" + host + "/ws"
		if got := h.websocketURL(req); got != want {
			t.Errorf("websocketURL for host %q = %q, want %q", host, got, want)
		}
	}
}

// A page served over TLS cannot open a ws:// socket, so the derived scheme has
// to follow the connection — directly, or as reported by a terminating proxy.
func TestWebSocketURLUsesSecureSchemeOverTLS(t *testing.T) {
	h := handlersWithWebSocketURL("")

	direct := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	direct.Host = "canvas.example"
	direct.TLS = &tls.ConnectionState{}
	if got := h.websocketURL(direct); got != "wss://canvas.example/ws" {
		t.Errorf("websocketURL over TLS = %q", got)
	}

	forwarded := httptest.NewRequest(http.MethodPost, "/v1/sessions/bootstrap", nil)
	forwarded.Host = "canvas.example"
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	if got := h.websocketURL(forwarded); got != "wss://canvas.example/ws" {
		t.Errorf("websocketURL behind a TLS proxy = %q", got)
	}
}
