# ThreatLens Setup Guide

This guide explains how to install, configure, run, test, and troubleshoot
ThreatLens in the current local-development mode.

ThreatLens has two applications:

- **Backend:** FastAPI API on `http://localhost:8000`
- **Frontend:** React/Vite web application on `http://localhost:5173`

The local mode uses SQLite, in-process caching and quota tracking, and the
development mock provider. Docker, PostgreSQL, Redis, and a Celery worker are
not required for this setup.

## 1. Prerequisites

Install the following tools:

- Python 3.12 or newer
- Node.js 20 LTS or newer
- npm
- Git

Verify the tools:

```bash
python --version
node --version
npm --version
git --version
```

The backend targets Python 3.12. Newer Python versions may work, but Python
3.12 is the recommended version for matching the project configuration.

## 2. Get the project

Clone the repository and enter its directory:

```bash
git clone <repository-url>
cd threatlens
```

If the repository is already available locally:

```bash
cd /path/to/threatlens
```

All commands below assume that the current directory is the repository root.

## 3. Configure the backend

Create a Python virtual environment:

```bash
cd backend
python -m venv .venv
```

Activate it:

```bash
# Linux or macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Windows Command Prompt
.venv\Scripts\activate.bat
```

Upgrade packaging tools and install runtime plus development dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Create the local environment file:

```bash
cp .env.example .env
```

On Windows, copy `.env.example` to `.env` using File Explorer or:

```powershell
Copy-Item .env.example .env
```

`backend/.env` is ignored by Git and must never be committed.

## 4. Backend environment variables

The default `.env` is suitable for local development. The important settings
are:

| Variable | Local value/purpose |
|---|---|
| `APP_ENV` | Keep `development` locally |
| `DEBUG` | Keep `true` locally |
| `DATABASE_URL` | Defaults to SQLite at `./threatlens.db` |
| `SECRET_KEY` | Replace `CHANGE_ME` with a local random value |
| `CORS_ORIGINS` | Allows the Vite frontend on ports 5173 |
| `MOCK_PROVIDERS` | Keep `true` when provider API keys are unavailable |
| `REDIS_URL` | Leave empty in local simplified mode |
| `CELERY_BROKER_URL` | Leave empty in local simplified mode |
| `CELERY_RESULT_BACKEND` | Leave empty in local simplified mode |

Generate a local secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Copy the output into `.env`:

```dotenv
SECRET_KEY=<generated-local-secret>
```

Provider keys are optional:

```dotenv
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
URLHAUS_AUTH_KEY=
OTX_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
```

When no real provider keys are configured, development mock behavior keeps the
local scanner usable. Real provider keys belong only in `backend/.env`.

## 5. Initialize the database

From the `backend` directory, apply the Alembic migrations:

```bash
alembic upgrade head
```

If the `alembic` command is not found, activate the virtual environment and
run:

```bash
python -m alembic upgrade head
```

This creates the local SQLite database at:

```text
backend/threatlens.db
```

The database is local runtime data and is ignored by Git.

To check the current migration:

```bash
alembic current
```

## 6. Start the backend

Keep the virtual environment active and run:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API is now available at:

- Health check: <http://127.0.0.1:8000/api/v1/health>
- OpenAPI documentation: <http://127.0.0.1:8000/docs>
- ReDoc documentation: <http://127.0.0.1:8000/redoc>

The health endpoint reports the local mode as degraded when Redis and the
worker are unavailable. This is expected because they are intentionally
disabled in the simplified setup. The database should report `up`.

To stop the backend, press `Ctrl+C`.

## 7. Configure the frontend

Open a second terminal at the repository root:

```bash
cd frontend
npm install
```

Create the frontend environment file:

```bash
cp .env.example .env
```

The default value is:

```dotenv
VITE_API_BASE_URL=http://localhost:8000/api/v1
```

Use `127.0.0.1` instead if the backend is being accessed through that host:

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

The backend CORS configuration already allows both local frontend hostnames.

## 8. Start the frontend

From `frontend`:

```bash
npm run dev
```

Open the URL printed by Vite, normally:

<http://localhost:5173>

The frontend includes:

- Scanner workspace
- URL, domain, IP, and hash validation
- Scan progress polling
- Risk verdict and score display
- Provider result status
- Session dashboard
- Session history
- About page

To stop the frontend, press `Ctrl+C`.

## 9. Run the project

You need two terminals.

### Terminal 1: backend

```bash
cd threatlens/backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Terminal 2: frontend

```bash
cd threatlens/frontend
npm run dev
```

Then open:

<http://localhost:5173>

For a quick smoke test:

1. Paste `example.com` into the scanner.
2. Click **Investigate**.
3. Wait for the scan result.
4. Review the verdict, score, severity, rationale, and provider rows.
5. Open **Dashboard** and **History** to confirm the session data appears.

## 10. Run tests and quality checks

### Backend tests

From `backend` with the virtual environment active:

```bash
pytest
```

Additional backend checks:

```bash
ruff check .
ruff format --check .
mypy
```

### Frontend tests

From `frontend`:

```bash
npm test
npm run lint
npm run build
```

`npm run build` runs TypeScript validation before creating the Vite production
bundle.

## 11. Useful development commands

### Backend

```bash
# Run without auto-reload
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Create a new migration after model changes
alembic revision --autogenerate -m "describe the change"

# Apply pending migrations
alembic upgrade head

# Show migration history
alembic history
```

### Frontend

```bash
# Start Vite on a specific port
npm run dev -- --host 127.0.0.1 --port 5173

# Build the production bundle
npm run build

# Preview a built bundle
npm run build
npm run preview
```

## 12. Local data and cleanup

The following are generated during development and are ignored by Git:

- `backend/threatlens.db`
- `backend/reports_output/`
- Python virtual environments and caches
- `frontend/node_modules/`
- `frontend/dist/`

To reset the local database and generated reports:

```bash
rm -f backend/threatlens.db
rm -rf backend/reports_output
cd backend
alembic upgrade head
```

On Windows PowerShell:

```powershell
Remove-Item backend\threatlens.db -ErrorAction SilentlyContinue
Remove-Item backend\reports_output -Recurse -Force -ErrorAction SilentlyContinue
Set-Location backend
alembic upgrade head
```

Do not delete `backend/.env` unless you have a backup of the local
configuration. Do not commit provider secrets.

## 13. Troubleshooting

### `ModuleNotFoundError: No module named ...`

Confirm that the backend virtual environment is active:

```bash
cd backend
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### `alembic: command not found`

Activate `.venv` or use the module form:

```bash
python -m alembic upgrade head
```

### Port 8000 is already in use

Find and stop the process using port 8000, or run the backend on another port:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

If the port changes, update `frontend/.env`:

```dotenv
VITE_API_BASE_URL=http://localhost:8001/api/v1
```

### Port 5173 is already in use

Start Vite on another port and add that origin to `CORS_ORIGINS` in
`backend/.env`:

```bash
npm run dev -- --port 5174
```

```dotenv
CORS_ORIGINS=http://localhost:5174,http://127.0.0.1:5174
```

Restart the backend after changing `.env`.

### The frontend says the API is unreachable

Check all of the following:

1. The backend terminal is still running.
2. `http://127.0.0.1:8000/api/v1/health` opens successfully.
3. `frontend/.env` contains the correct `VITE_API_BASE_URL`.
4. The frontend was restarted after changing `.env`.
5. The frontend host and port are included in `CORS_ORIGINS`.

### Health reports Redis or worker as unavailable

This is expected in local simplified mode. Leave these variables empty:

```dotenv
REDIS_URL=
CELERY_BROKER_URL=
CELERY_RESULT_BACKEND=
```

The local scan flow uses in-process behavior instead.

### Provider results are skipped

This is expected when provider keys are empty. Either keep
`MOCK_PROVIDERS=true` for local development or add valid provider keys to
`backend/.env`.

## 14. Production warning

This guide is for local development only. Before deployment:

- Use PostgreSQL instead of local SQLite.
- Add Redis for distributed state.
- Run Celery workers.
- Disable mock providers.
- Set `DEBUG=false`.
- Use a strong production `SECRET_KEY`.
- Configure explicit production CORS origins.
- Move report storage to durable protected storage.
- Configure TLS, secrets, backups, logs, metrics, and alerts.

See the project [README](./README.md) and the documentation in `docs/` for the
current architecture, security model, provider behavior, and remaining work.
