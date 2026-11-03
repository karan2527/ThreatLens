# ThreatLens

ThreatLens is a local cyber threat-intelligence workspace. Enter a URL,
domain, IP address, or file hash and it returns a single explainable
assessment from the configured security checks.

## Features

- Investigate URLs, domains, IPv4/IPv6 addresses, and MD5/SHA-1/SHA-256 hashes.
- Normalize indicators so `www.google.com` and `google.com` are treated as the
  same standalone domain.
- Query configured providers such as VirusTotal, AbuseIPDB, URLhaus, OTX, and
  Google Safe Browsing.
- Analyze domains with DNS A, AAAA, MX, NS, TXT, and CNAME lookups.
- Check domain registration/RDAP data, age, registrar, nameservers, SPF, DKIM,
  DMARC, and DNS configuration anomalies.
- Combine provider evidence into a verdict, severity, risk score, rationale,
  and provider status.
- View session-scoped scan history and dashboard metrics.
- Use a dark responsive React interface with anonymous browser sessions.

ThreatLens is intended for local development and learning. A `CLEAN` result
does not guarantee that an indicator is safe.

## Requirements

- Python 3.12+
- Node.js 20+
- npm

## Run locally

### 1. Start the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Windows: copy .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

The backend uses SQLite by default and creates `backend/threatlens.db`.
Optional provider API keys belong in the local, ignored `backend/.env` file.
Keep this terminal running while using the frontend. The backend health check
is available at <http://localhost:8000/api/v1/health>.

### 2. Start the frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173>.
Keep both the backend and frontend terminals running. If the browser says that
the API is not reachable, verify that the backend terminal is still running
and that <http://localhost:8000/api/v1/health> returns JSON.

## Check the project

Backend:

```bash
cd backend
pytest
ruff check .
mypy
```

Frontend:

```bash
cd frontend
npm test -- --run
npm run lint
npm run build
```

## Project layout

```text
backend/app/       FastAPI API, scanning, providers, scoring, and database code
backend/tests/     Backend unit, security, and integration tests
frontend/src/      React application, API client, styles, and frontend tests
```

Docker, Redis, PostgreSQL, and Celery are not required for the simplified local
mode. Production deployment has not been configured.

## License

See [LICENSE](./LICENSE).
