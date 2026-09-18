# myPol Go Realtime Service

Session and security foundation for the collaborative canvas. Canvas traffic
(WebSocket, WebTransport, WebRTC) is deliberately **not** implemented yet.

## What this service does today

- Validates ES256 canvas access tokens minted by the .NET API, using only the
  public key. It can verify a token but never create one.
- Establishes a `CanvasSession` and issues a **single-use, 30-second connection
  ticket** for opening a realtime transport.
- Serves a **canvas WebSocket**: note-scoped rooms, server-authoritative
  presence, and an envelope-v2 relay with separate ephemeral and reliable
  queues, per-connection token-bucket rate limits, and permission enforced by
  message class.
- Serves **WebTransport over HTTP/3** on its own listener, carrying previews as
  datagrams and final state on a reused reliable stream. Rooms, presence,
  permissions and rate limits are the same code as the WebSocket path — a second
  way in must not be a weaker one.
- Exposes an HMAC-authenticated internal control plane so .NET can revoke access
  immediately rather than waiting for a token to expire — revocation closes live
  sockets, and a permission change is applied in place without dropping them.

- Routes **WebRTC signalling** peer to peer. `rtc.offer` / `rtc.answer` /
  `rtc.candidate` are delivered to exactly one named connection in the sender's
  own room, never broadcast, and are refused entirely once a room exceeds
  `WEBRTC_MAX_PEERS`. ICE configuration is served from the authenticated
  bootstrap so TURN credentials stay out of the frontend bundle.

Interest filtering and the binary codec are later phases and deliberately absent.
Go is a signalling *router* only — it never participates in the negotiation, and
perfect negotiation is the browser's responsibility.

### Enabling WebTransport locally

```bash
openssl ecparam -genkey -name prime256v1 -noout -out wt.key
openssl req -x509 -new -key wt.key -out wt.crt -days 365 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

export WEBTRANSPORT_ADDR=:8443 TLS_CERT_FILE=./wt.crt TLS_KEY_FILE=./wt.key
```

Browsers reject self-signed certificates for WebTransport unless Chrome is
started with `--origin-to-force-quic-on` and a `--ignore-certificate-errors-spki-list`
hash, so a locally trusted certificate is easier for manual testing.

## Run

```bash
export CANVAS_JWT_PUBLIC_KEY_FILE=./keys/canvas-public.pem
export INTERNAL_HMAC_CURRENT_KEY_ID=hmac-2026-01
export INTERNAL_HMAC_CURRENT_SECRET=<secret>

# Optional. Both accept the machine's current LAN address without naming it, so
# joining a different network needs no edit here.
export ALLOWED_ORIGINS="http://localhost:3000,http://192.168.*.*:3000,http://10.*.*.*:3000"
# WEBSOCKET_URL left unset: derived from each bootstrap request's Host.

go run ./cmd/server
```

The public key must be the PEM `SubjectPublicKeyInfo` half of the ES256 key the
.NET API signs with:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out canvas.key
openssl pkcs8 -topk8 -nocrypt -in canvas.key -out canvas-private.pem  # -> .NET
openssl ec -in canvas.key -pubout -out canvas-public.pem              # -> Go
```

> This repository is not a git checkout, so Go's VCS stamping fails. Build with
> `GOFLAGS=-buildvcs=false` (or `go build -buildvcs=false ./...`).

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness — stays 200 while draining |
| `GET` | `/readyz` | none | Readiness — 503 while draining |
| `POST` | `/v1/sessions/bootstrap` | Canvas JWT (Bearer) | Session + connection ticket |
| `GET` | `/ws?ticket=…` | One-time ticket | Canvas WebSocket: rooms, presence, relay |
| `GET` | `/wt?ticket=…` | One-time ticket | Canvas WebTransport (HTTP/3), separate listener |
| `POST` | `/internal/v1/sessions/revoke` | HMAC | End one session |
| `POST` | `/internal/v1/sessions/permission` | HMAC | Change a live session's permission |
| `POST` | `/internal/v1/notes/{noteId}/users/{userId}/revoke` | HMAC | End every session a user holds on a note |

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `HTTP_ADDR` | `:8080` | |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma separated. An entry may contain `*`, which matches any run of characters except `/` — `http://192.168.*.*:3000` covers a development machine whose LAN address changes with the network. Production should list literal origins |
| `CANVAS_JWT_ISSUER` | `mypol-api` | |
| `CANVAS_JWT_AUDIENCE` | `canvas-realtime` | |
| `CANVAS_JWT_PUBLIC_KEY_FILE` | — | **Required**; startup fails without it |
| `CANVAS_JWT_LEEWAY_SECONDS` | `5` | Clock skew allowance |
| `INTERNAL_HMAC_CURRENT_KEY_ID` / `_SECRET` | — | Empty disables internal control |
| `INTERNAL_HMAC_PREVIOUS_KEY_ID` / `_SECRET` | — | Kept live during rotation |
| `INTERNAL_HMAC_MAX_CLOCK_SKEW_SECONDS` | `30` | |
| `CONNECTION_TICKET_TTL_SECONDS` | `30` | |
| `CONNECTION_TICKET_SWEEP_SECONDS` | `10` | |
| `SESSION_HEARTBEAT_SECONDS` | `15` | Advertised to clients |
| `SESSION_IDLE_TIMEOUT_SECONDS` | `45` | |
| `WEBSOCKET_URL` / `WEBTRANSPORT_URL` | — | Advertised at bootstrap. An empty `WEBSOCKET_URL` derives the address from the request's own `Host`, which is what lets a development machine change network without reconfiguration; set it explicitly behind a proxy. WT is omitted when empty |
| `WEBTRANSPORT_ADDR` | — | UDP listener for HTTP/3. Empty disables WebTransport |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | — | Required for WebTransport; QUIC has no plaintext mode |
| `MAX_DATAGRAM_BYTES` | `1100` | Frames above this fall back to the reliable stream |
| `WEBRTC_MAX_PEERS` | `6` | Room size above which signalling is refused |
| `STUN_URLS` | `stun:stun.l.google.com:19302` | Comma separated |
| `TURN_URLS` / `TURN_USERNAME` / `TURN_CREDENTIAL` | — | Served via bootstrap, never to the bundle |
| `SHUTDOWN_GRACE_SECONDS` | `5` | |

No secret has a usable default: an unset HMAC secret leaves the control plane
disabled rather than open.

## Internal control signature

Requests are signed over a canonical string, rebuilt identically by .NET's
`HmacRequestSigner`:

```text
METHOD \n PATH \n TIMESTAMP \n NONCE \n SHA256(BODY)
```

Sent as `X-Service-Id`, `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`
(lowercase hex HMAC-SHA256). The timestamp bounds replay, the nonce blocks exact
replay inside that window, and the body hash prevents payload swapping.

## Structure

```text
go-realtime/
├── cmd/server/            entrypoint, sweep loop, graceful shutdown
└── internal/
    ├── config/            environment configuration
    ├── domain/            session, ticket, permission, store ports
    ├── application/       session service (bootstrap, revoke, sweep)
    ├── security/          ES256 validation, ticket generation, HMAC
    ├── infrastructure/    in-memory session and ticket stores
    ├── transport/         HTTP handlers, router, CORS
    └── testsupport/       token minting for tests
```

## Tests

```bash
GOFLAGS=-buildvcs=false go test ./...
```
# Load testing

Phase 19 tooling lives in `cmd/loadtest`. It uses the real bootstrap/ticket
flow and supports Go WebSocket and WebTransport, JSON and binary previews, and
the `distributed`, `mostly-viewing`, `multi-page`, `viewports`, and `hotspot`
scenarios. It records preview p50/p95/p99, messages/sec, bytes, commit relay
delivery, interest fan-out, queue depth, and dropped ephemeral frames.

Run it from this directory with a local development key matching the server's
public key:

```powershell
go run ./cmd/loadtest -base-url http://127.0.0.1:8081 -connections 100 -duration 30s -scenario hotspot -transport websocket -encoding json -report ..\docs\performance\canvas-realtime-load-test-report.md
```

For 500/1000-user runs, raise the server bootstrap IP burst/rate for the test
and use a separate report file per matrix cell. Use
`scripts/run-load-test.ps1 -ServerPid <pid>` to capture Windows CPU/RAM beside
the runner output. The full matrix and interpretation rules are in
`docs/performance/canvas-realtime-load-test-report.md`.

The runner deliberately does not call a signaling-only path a WebRTC capacity
test. WebRTC small-room results require real browser ICE/DataChannel peers and
must be recorded separately. Do not publish a same-viewport capacity number
until the hotspot row also has browser FPS and main-thread measurements.
