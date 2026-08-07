# AI2SQL Connector

Connects a user's **local database** (localhost / private network) to the
AI2SQL cloud. Two binaries, one repo:

- **`cmd/connector`** — what the user downloads. Single binary, no installer,
  no dependencies. Serves a small web UI on `127.0.0.1:5533`, takes a pairing
  code, and holds one outbound TLS WebSocket to the relay. Forwards tunnel
  streams to the local database over plain TCP.
- **`cmd/relay`** — runs on AI2SQL infrastructure. Accepts connector
  WebSockets, exposes each active tunnel as an ordinary `host:port`. The
  AI2SQL backend dials that address exactly like any public database —
  **zero changes to existing connection/query code**.

```
user's machine                         AI2SQL cloud
┌─────────────────────┐               ┌─────────────────────┐
│ local DB ◀── TCP ── │ connector ══▶ │ relay ◀── TCP ────  │ backend
│ (1433/3306/5432)    │  outbound WS  │  per-tunnel port    │ (unchanged)
└─────────────────────┘               └─────────────────────┘
```

Credentials never pass through the connector as such — they travel inside the
database's own wire protocol over the tunnel, the same bytes that would go to
a public host. The connector machine exposes **no inbound ports**.

## Flow

1. Backend detects a local host (`detectHostType` already live in
   `api/server.js`) → calls `POST /pair` on the relay → shows the code.
2. User downloads the connector, runs it, browser opens, enters the code,
   picks the local DB (SQL Server / MySQL / PostgreSQL presets).
3. Relay marks the tunnel active; backend polls `GET /tunnel/{code}`, gets
   `public_addr`, saves it as the connection host. Done.

## Run locally

```bash
go test ./...                       # end-to-end tunnel test, no DB needed

go run ./cmd/relay --listen :8090 --public-host 127.0.0.1 --api-secret dev
curl -X POST -H 'X-Api-Secret: dev' localhost:8090/pair   # -> {"code":"..."}
go run ./cmd/connector --relay ws://localhost:8090/ws     # UI opens
```

Headless: `connector --no-ui --code XXXXXX --target localhost:1433`

## Build / release

```bash
GOOS=windows GOARCH=amd64 go build -o dist/ai2sql-connector-windows-amd64.exe ./cmd/connector
GOOS=darwin  GOARCH=arm64 go build -o dist/ai2sql-connector-macos-arm64      ./cmd/connector
GOOS=linux   GOARCH=amd64 go build -o dist/ai2sql-relay-linux-amd64          ./cmd/relay
```

## Before shipping (not done yet)

- **TLS**: run the relay behind a TLS terminator (Caddy/nginx) so connectors
  dial `wss://`. The binary itself speaks plain WS.
- **Code signing**: unsigned .exe hits SmartScreen, unsigned .dmg hits
  Gatekeeper. Windows cert + Apple notarization are the real release cost.
- **Backend integration**: on `Database Connect Rejected`, call `/pair`,
  show the code + download link, poll `/tunnel/{code}`, save `public_addr`.
- Relay deployment target (needs a persistent host — not Vercel).
- Multi-tunnel per user, reconnect keeping the same port, metrics.
