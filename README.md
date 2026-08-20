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
- Exposes an HMAC-authenticated internal control plane so .NET can revoke access
  immediately rather than waiting for a token to expire — revocation closes live
  sockets, and a permission change is applied in place without dropping them.

WebTransport, WebRTC signalling, interest filtering and the binary codec are
later phases and deliberately absent.

## Run

```bash
export CANVAS_JWT_PUBLIC_KEY_FILE=./keys/canvas-public.pem
export INTERNAL_HMAC_CURRENT_KEY_ID=hmac-2026-01
export INTERNAL_HMAC_CURRENT_SECRET=<secret>
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
| `POST` | `/internal/v1/sessions/revoke` | HMAC | End one session |
| `POST` | `/internal/v1/sessions/permission` | HMAC | Change a live session's permission |
| `POST` | `/internal/v1/notes/{noteId}/users/{userId}/revoke` | HMAC | End every session a user holds on a note |

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `HTTP_ADDR` | `:8080` | |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma separated |
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
| `WEBSOCKET_URL` / `WEBTRANSPORT_URL` | — | Advertised at bootstrap; WT omitted when empty |
| `WEBRTC_MAX_PEERS` | `6` | |
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
