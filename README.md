# ThreatLens

**See the threat. Understand the risk. Make informed security decisions.**

ThreatLens is a privacy-conscious cyber threat intelligence and malware-analysis
workspace. It accepts an indicator, checks it against configured threat
intelligence providers, correlates the evidence, and returns one explainable
risk assessment.

Supported indicators are:

- URLs
- Domains
- IP addresses
- File hashes

The project is currently a functional local-development application. It is
not yet a production deployment.

## What the product does

ThreatLens is designed to make threat-intelligence lookups easier to interpret.
Instead of showing disconnected provider responses, it:

1. Validates and normalizes the submitted indicator.
2. Creates an anonymous browser session.
3. Runs the relevant provider checks.
4. Caches eligible provider responses and applies quota controls.
5. Correlates the available evidence.
6. Calculates a versioned risk score.
7. Returns a verdict, severity, rationale, provider coverage, and raw normalized
   provider results.
8. Keeps the scan available in the session-scoped history and dashboard.

The UI is intentionally aimed at careful investigation rather than automated
decision-making. `CLEAN` means that no malicious finding was returned by
enough relevant successful checks; it does not prove that an indicator is safe.

## Current status

| Area | Status |
|---|---|
| Local FastAPI backend | Implemented |
| SQLite database and Alembic migration | Implemented |
| Indicator validation and normalization | Implemented |
| Provider adapter framework | Implemented |
| VirusTotal adapter | Implemented |
| AbuseIPDB, URLhaus, OTX, and Google Safe Browsing adapters | Implemented |
| Provider caching and local quota handling | Implemented |
| Correlation and `scoring_v1` risk engine | Implemented |
| Anonymous sessions and ownership checks | Implemented |
| Scan, history, dashboard, and report APIs | Implemented |
| React scanner, results, dashboard, history, and About views | Implemented |
| Dark professional UI refresh | Implemented |
| Backend unit, security, and integration tests | Implemented |
| Frontend Vitest and React Testing Library tests | Implemented |
| Production deployment | Not started |
| Final acceptance audit and handover | Not started |

## What has been implemented

### Backend foundation

- FastAPI application entrypoint in `backend/app/main.py`.
- Centralized Pydantic settings in `backend/app/config.py`.
- Async SQLAlchemy database access with SQLite support for local development.
- Alembic migration setup and the initial schema migration.
- Structured application errors and request-context handling.
- Health endpoint at `GET /api/v1/health`.
- CORS configuration and baseline response security headers:
  - `X-Request-ID`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Content-Security-Policy`

### Indicator processing

The backend validates indicators before provider calls. The implementation
handles:

- URL parsing and normalization.
- Domain validation and canonicalization.
- IPv4 and IPv6 validation.
- SHA-256, SHA-1, and MD5-style file hash validation.
- Indicator type detection and explicit type checks.
- Stable canonical values used by caching and correlation.

The frontend also has Zod validation for immediate user feedback, but the
backend remains the authoritative validation boundary.

### Provider integrations

The provider framework supports common status and verdict semantics, including
`SUCCESS`, `SKIPPED`, `NOT_FOUND`, `FAILED`, `TIMEOUT`, and rate-limited
responses.

Implemented adapters:

- VirusTotal
- AbuseIPDB
- URLhaus
- AlienVault OTX
- Google Safe Browsing

Provider API keys are read from `backend/.env`, are never returned in
normalized results, and are not committed to Git. In development, the mock
provider mode can be used when real provider keys are not configured.

Provider-specific behavior and configuration is documented in
[docs/providers.md](docs/providers.md).

### Caching, quota, and orchestration

- Provider cache keys use provider, indicator type, and a canonical indicator
  hash.
- Successful, skipped, and not-found responses can be cached.
- Failed, timed-out, rate-limited, and unavailable responses are not cached.
- Not-found responses use a shorter cache lifetime.
- Local development uses in-process cache and quota stores.
- Scan creation is limited to 20 scans per hour per anonymous session.
- Requests are limited to 60 requests per minute per client key.
- A session may have up to 2 concurrent scans.
- The current local scan flow runs in-process and does not require Redis or a
  Celery worker.

Operational details are in [docs/operations.md](docs/operations.md).

### Risk scoring and correlation

The `scoring_v1` policy combines provider evidence with indicator-specific
weights. It includes:

- Provider weight renormalization when a provider is unavailable.
- Provider-specific score calculations.
- Correlation of independent findings.
- Authoritative overrides for selected provider signals.
- Conflict handling.
- Explainable verdict rationale.
- Severity bands from LOW through CRITICAL.

The full scoring policy is documented in
[docs/scoring.md](docs/scoring.md).

### Security and privacy

ThreatLens currently uses anonymous browser sessions rather than accounts.
Implemented protections include:

- HMAC-SHA256 session ownership digests instead of storing raw session cookies.
- `HttpOnly` and `SameSite=Lax` cookies.
- Secure cookies in production.
- `X-Requested-With` validation for state-changing requests.
- Session ownership checks on scan and report access.
- Request IDs and baseline security response headers.
- Redaction of API keys, cookies, authorization values, and session tokens in
  logs.
- Path containment checks for generated report downloads.
- Production configuration validation:
  - `DEBUG=false`
  - a sufficiently long `SECRET_KEY`
  - explicit CORS origins
  - mock providers disabled

See [docs/security.md](docs/security.md) for the local security model.

### Reports and history

The backend supports:

- JSON report generation and download.
- PDF report generation through ReportLab.
- Session-scoped scan history.
- Session-scoped dashboard totals and recent investigations.
- Provider-level result details in completed scan results.

Generated reports are local development artifacts and are intentionally ignored
by Git.

### Frontend

The React/Vite frontend includes:

- Responsive ThreatLens shell and navigation.
- Dark professional visual theme.
- Landing/scanner workspace.
- URL, domain, IP, and hash input support.
- Scan submission and progress polling.
- Completed assessment view with verdict, score, severity, rationale, and
  provider status.
- Session dashboard with scan metrics and verdict distribution.
- Session history view.
- About view explaining the product model.
- Mobile navigation.
- Frontend validation with Zod.
- Vitest and React Testing Library coverage for the scanner shell and validation.

The frontend API base URL can be set with `VITE_API_BASE_URL`. When it is not
set, the frontend targets the current page hostname on port `8000`, which
allows `localhost` and `127.0.0.1` sessions to behave consistently.

## Architecture

```text
React + Vite frontend
        |
        | HTTP / JSON, anonymous session cookie, CSRF header
        v
FastAPI API
        |
        +-- Indicator validation and normalization
        +-- Scan orchestration
        +-- Provider adapters
        +-- Cache and quota services
        +-- Correlation and risk engine
        +-- History, dashboard, and report services
        |
        v
SQLite (local mode) / PostgreSQL target for deployment
```

The code is organized into:

- `backend/app/api/` — API routers and request handling.
- `backend/app/core/` — security, logging, errors, quota, and rate limiting.
- `backend/app/integrations/` — external provider adapters.
- `backend/app/models/` — SQLAlchemy persistence models.
- `backend/app/schemas/` — Pydantic request and response schemas.
- `backend/app/services/` — scanning, orchestration, caching, history,
  correlation, scoring, and reports.
- `backend/app/utils/` — validation, hashing, and IP utilities.
- `backend/app/workers/` — Celery integration prepared for a future deployed
  worker mode.
- `frontend/src/` — React application, API client, styles, and tests.

## API surface

The API is mounted below `/api/v1`. The main implemented capabilities are:

| Endpoint area | Purpose |
|---|---|
| `GET /health` | Report database, Redis, and worker availability |
| `POST /scans` | Create an indicator investigation |
| `GET /scans/{scan_id}` | Read owned scan status and progress |
| `GET /scans/{scan_id}/results` | Read owned completed scan results |
| `GET /history` | Read anonymous-session scan history |
| `GET /dashboard` | Read anonymous-session dashboard metrics |
| Report endpoints | Generate and download owned JSON/PDF reports |

State-changing requests require the expected `X-Requested-With` header.

## Local setup

### Prerequisites

- Python 3.12 or newer
- Node.js 20 LTS or newer
- npm

Docker and Docker Compose are not required for the current local mode. The
placeholder Docker and infrastructure files were removed because deployment
has not started yet.

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

The backend defaults to SQLite at `backend/threatlens.db`. Provider keys can be
added to the ignored `backend/.env` file when real provider checks are needed.
Never commit that file.

### Frontend

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server normally runs on port `5173`.

### Quality checks

Backend commands:

```bash
cd backend
pytest
ruff check .
ruff format --check .
mypy
```

Frontend commands:

```bash
cd frontend
npm test
npm run lint
npm run build
```

## Files and documentation

- [PROGRESS.md](./PROGRESS.md) — gated implementation progress and project
  decisions.
- [docs/operations.md](./docs/operations.md) — local cache, quota, and
  operational behavior.
- [docs/providers.md](./docs/providers.md) — provider credentials and result
  semantics.
- [docs/scoring.md](./docs/scoring.md) — `scoring_v1` scoring policy.
- [docs/security.md](./docs/security.md) — security and privacy behavior.
- [docs/README.md](./docs/README.md) — documentation index.

## What remains to be implemented

### 1. Production deployment

The largest remaining milestone is production deployment. It still needs:

- A production hosting configuration for the frontend and backend.
- PostgreSQL provisioning and migration execution.
- Redis provisioning for distributed cache, quota, and rate-limiter state.
- A real Celery worker deployment and task routing.
- Production report storage rather than local filesystem storage.
- Secret management and provider-key injection.
- Production CORS, cookie, domain, and TLS configuration.
- Health checks, logs, metrics, and alerting.
- Backup, restore, and database-retention procedures.

The original hosting direction is Vercel for the frontend and Render for the
backend, but that deployment has not been configured or verified.

### 2. External provider readiness

- Obtain and validate provider API keys.
- Confirm each provider's licensing, attribution, and free-tier limits.
- Decide whether Google Safe Browsing should be enabled.
- Verify live provider behavior and response changes.
- Add provider-specific monitoring and retry policies.
- Confirm that provider usage and caching comply with each provider's terms.

### 3. Background processing

The Celery integration exists, but local scanning currently runs in-process.
Deployment still needs:

- Worker startup and deployment configuration.
- Redis broker and result backend configuration.
- Durable task retry and failure handling.
- Monitoring for queued, running, stuck, and failed scans.
- Clear behavior when workers or Redis are unavailable.

### 4. Product and UX completion

Potential follow-up product work includes:

- More detailed provider evidence views.
- Better scan progress stage visibility.
- Report download controls in the frontend.
- Pagination controls and filtering for history.
- Expiration or cleanup UX for the 24-hour anonymous session.
- Optional authenticated accounts if long-term history is required.
- Empty, degraded, and provider-unavailable states reviewed with live data.
- Accessibility review with keyboard navigation and screen readers.

### 5. Final quality and release audit

Before release, the project still needs:

- Full backend and frontend quality gates in a clean environment.
- Live integration verification with selected providers.
- Production configuration verification.
- Dependency and license review.
- Security review of the deployed topology.
- Performance and concurrency testing with PostgreSQL and Redis.
- Browser/device acceptance testing.
- Final documentation and operational handover.
- Confirmation of the final license; MIT is currently an assumption for the
  skeleton and has not been formally confirmed.

## Known limitations

- Local cache, quota, and rate-limiter stores are process-local.
- The local SQLite setup should not be used with multiple API workers.
- Redis, PostgreSQL, and a running Celery worker are not part of local mode.
- Provider results are limited when API keys are not configured.
- Mock providers are intended for development only.
- Anonymous history is tied to the browser session and is not an account.
- Local report files are not durable production storage.
- `scoring_v1` is a ThreatLens project policy, not an industry standard.
- No production deployment has been completed.

## Project decisions

- Frontend package manager: npm.
- Python environment: virtual environment.
- Intended use: personal / learning during the skeleton phase.
- Anonymous session TTL: 24 hours.
- Intended scan retention: 30 days.
- Development mock providers: enabled only outside production.
- Initial database: SQLite-compatible schema.
- Planned deployment direction: Vercel + Render.
- Repository visibility: private initially.

## License

The repository includes an MIT license file. The project notes still list final
license confirmation as a release decision; verify that the intended license
matches the final distribution plan before publishing.
