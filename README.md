# AuthService

Production-ready authentication service with Google OAuth 2.0, JWT access/refresh tokens (with rotation), multi-device session management on Redis, PostgreSQL persistence, Prometheus metrics, structured logging, rate limiting, and Swagger API docs.

## Features

- Google OAuth 2.0 login (profile + email scopes)
- JWT access and refresh tokens (HS256)
  - Token rotation on refresh (old refresh token invalidated)
  - Blacklisting for token revocation (logout, revoke)
- Multi-device sessions stored in Redis (device + IP, per-session revoke)
- Rate limiting per IP and endpoint (Redis-backed)
- CORS, security headers, panic recovery, compression, request logging w/ request ID
- Prometheus metrics at `/metrics`
- Health and readiness probes at `/health` and `/ready`
- Swagger UI at `/api/docs` (OpenAPI 2.0)

## Tech stack

- Go 1.25.3
- chi router, zerolog, swaggo/http-swagger
- PostgreSQL 16 (persistent users)
- Redis 7 (sessions, refresh tokens, blacklist, rate limiting, cache)
- Docker / Docker Compose
- Prometheus client for Go

## Architecture (high level)

- `cmd/server/main.go` wires everything:
  - Load config from env (.env supported)
  - Connect to PostgreSQL and Redis (with retry)
  - Run idempotent DB migrations
  - Create services: OAuth, JWT, Session
  - Register middleware: recover, logging, metrics, security headers, CORS, timeout, gzip
  - Mount routes: health, metrics, Swagger, and `/api/v1/auth/*`
- Services layer (`internal/services`): OAuth (Google), JWT, Session
- Data layer (`internal/database`): PostgreSQL + Redis helpers
- HTTP layer (`internal/handlers`): Auth + Health endpoints
- Middleware (`internal/middleware`): JWT auth, logging, metrics, rate limiting, CORS, security
- Cache helpers (`pkg/cache`) and utilities (`pkg/utils`)

## Folder structure

- `cmd/server/` – app entrypoint
- `internal/database/` – Postgres and Redis wrappers + user queries
- `internal/handlers/` – HTTP handlers (auth, health)
- `internal/middleware/` – JWT, logging, metrics, headers, rate limit
- `internal/services/` – OAuth, JWT, session logic
- `internal/models/` – core domain models (User, SessionInfo)
- `pkg/cache/` – generic Redis JSON cache + user cache helpers
- `pkg/config/` – configuration loader/validator
- `pkg/utils/` – responses, cookies, IP, pagination, retry
- `migrations/` – SQL migrations (users table)
- `docs/` – Swagger spec (swagger.yaml/.json)
- `docker/` – Dockerfile

## API overview

Base path: `http://localhost:8080`

- Health
  - GET `/health` – liveness
  - GET `/ready` – readiness incl. Postgres/Redis checks
- Docs & Metrics
  - GET `/api/docs` – Swagger UI (doc.json under `/api/docs/doc.json`)
  - GET `/metrics` – Prometheus metrics
- Auth (v1)
  - GET `/api/v1/auth/google/login` – redirect to Google (sets `oauth_state` cookie)
  - GET `/api/v1/auth/google/callback?state=...&code=...` – completes login, sets cookies and redirects to frontend
  - POST `/api/v1/auth/refresh` – rotate tokens (cookie or JSON body: `{ "refresh_token": "..." }`)
  - Protected (requires access token via `Authorization: Bearer` or `access_token` cookie):
    - GET `/api/v1/auth/me` – current user profile
    - POST `/api/v1/auth/logout` – logout everywhere (revoke tokens + sessions, clear cookies)
    - GET `/api/v1/auth/sessions` – list active sessions (device, IP, location)
    - DELETE `/api/v1/auth/sessions/{id}` – revoke one session (device)
    - POST `/api/v1/auth/sessions/revoke-others` – revoke all except current

Swagger spec lives in `docs/swagger.yaml`; UI is served by the app at `/api/docs`.

## Configuration

Configuration is loaded from environment variables (with `.env` support in development). Required variables:

- `POSTGRES_PASSWORD` – Postgres password
- `GOOGLE_CLIENT_ID` – Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` – Google OAuth Client Secret
- `JWT_SECRET` – HS256 secret (≥ 32 bytes)

Useful optional vars (defaults in parentheses):

- Server
  - `ENV` (development) – affects cookie Secure flag
  - `PORT` (8080)
  - `FRONTEND_URL` (http://localhost:3000) – redirect after login
- PostgreSQL
  - `POSTGRES_HOST` (localhost) | `POSTGRES_PORT` (5432)
  - `POSTGRES_DB` (authdb) | `POSTGRES_USER` (authuser)
  - `POSTGRES_MAX_CONNS` (25)
- Redis
  - `REDIS_HOST` (localhost) | `REDIS_PORT` (6379)
  - `REDIS_PASSWORD` (empty) | `REDIS_DB` (0) | `REDIS_POOL_SIZE` (100)
- OAuth
  - `AUTH_REDIRECT_URL` (http://localhost:8080/api/v1/auth/google/callback)
  - `GOOGLE_USER_INFO` (https://www.googleapis.com/oauth2/v2/userinfo)
- JWT
  - `JWT_ACCESS_EXPIRY` (15m) | `JWT_REFRESH_EXPIRY` (168h = 7d)
- CORS
  - `ALLOWED_ORIGINS` (http://localhost:3000) – comma-separated list
- Rate limiting
  - `RATE_LIMIT_REQUESTS` (100) | `RATE_LIMIT_WINDOW` (1m)
- Cache
  - `CACHE_ENABLED` (true) | `CACHE_USER_TTL` (15m) | `CACHE_SESSION_TTL` (5m)

Example `.env` (development):

```
ENV=development
PORT=8080
FRONTEND_URL=http://localhost:3000

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=authdb
POSTGRES_USER=authuser
POSTGRES_PASSWORD=your-strong-password
POSTGRES_MAX_CONNS=25

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_POOL_SIZE=100

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
AUTH_REDIRECT_URL=http://localhost:8080/api/v1/auth/google/callback
GOOGLE_USER_INFO=https://www.googleapis.com/oauth2/v2/userinfo

JWT_SECRET=please-use-32-bytes-minimum-secret-string________
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

ALLOWED_ORIGINS=http://localhost:3000
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m
```

## Run with Docker

Prerequisites: Docker and Docker Compose.

1) Create a `.env` file at repository root and set the variables above (at minimum: `POSTGRES_PASSWORD`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `JWT_SECRET`, and `REDIS_PASSWORD` if you keep Redis auth on).

2) Start the stack:

```powershell
# From repo root
docker-compose up -d --build
```

- API: http://localhost:8080
- Swagger: http://localhost:8080/api/docs
- Health: http://localhost:8080/health, http://localhost:8080/ready
- Metrics: http://localhost:8080/metrics

Note: The sample `docker-compose.yml` sets `ENV=production`. In production this is correct, but for local browser testing over HTTP you may prefer `ENV=development` so auth cookies aren’t marked Secure (otherwise browsers won’t set them on http:// URLs).

## Run locally (without Docker)

Prerequisites:
- Go 1.25.3
- PostgreSQL 16 running locally
- Redis 7 running locally

Steps:

1) Ensure the `pgcrypto` extension is available in the database (used by `gen_random_uuid()`):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

2) Export environment variables (see `.env` example) or create a `.env` file.

3) Run the server:

```powershell
go run ./cmd/server
```

The app runs database migrations automatically on start.

## Auth flow (quick start)

1) Frontend hits `GET /api/v1/auth/google/login` → service sets `oauth_state` cookie and redirects to Google.
2) After consent, Google redirects to `/api/v1/auth/google/callback?state=...&code=...`.
3) Service verifies state, fetches Google profile, upserts the user, generates a token pair, creates a session, sets cookies:
   - `access_token` (HttpOnly; ~15m)
   - `refresh_token` (HttpOnly; ~7d)
   - `session_id` (HttpOnly; ~7d)
4) Redirects to `FRONTEND_URL`.

Use `Authorization: Bearer <access_token>` header OR `access_token` cookie for protected endpoints.

## Metrics and observability

- Prometheus metrics: `/metrics`
- Structured logs: zerolog; request-scoped `X-Request-ID` header is added and propagated

## Testing

Run all tests:

```powershell
go test ./...
```

Some tests spin up in-memory Redis (miniredis) and do not require external services. If a test requires env vars (e.g., JWT_SECRET), provide them via your shell or a `.env` file.

## Troubleshooting

- Cookies not set locally in browser: if `ENV=production`, cookies are `Secure` and won’t be set over HTTP. Use `ENV=development` for local testing or serve over HTTPS.
- Database migration error about `gen_random_uuid()`:
  - Ensure `CREATE EXTENSION IF NOT EXISTS pgcrypto;` has been run in your database.
- 401 Unauthorized on protected routes:
  - Ensure you send `Authorization: Bearer <access_token>` OR have the `access_token` cookie from a recent login.
- 429 Too Many Requests:
  - You’ve hit the rate limit for the endpoint; check `RATE_LIMIT_*` settings.
- CORS issues:
  - Set `ALLOWED_ORIGINS` to include your frontend origin(s).

## License

MIT. See `LICENSE`.
