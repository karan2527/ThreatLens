# ThreatLens Progress

## Step status

| Step | Title | Status |
|---:|---|---|
| 0 | Pre-flight questions and decisions | DONE |
| 1 | Repository, tooling and project skeleton | DONE |
| 2 | Docker Compose, configuration and health endpoint | DONE (local simplified mode) |
| 3 | Database models and Alembic migrations | DONE (SQLite-compatible) |
| 4 | Indicator validation and normalization | DONE |
| 5 | Core security layer | DONE (local fallback) |
| 6 | Provider framework and VirusTotal adapter | DONE |
| 7 | Additional provider adapters | DONE |
| 8 | Caching and provider quota management | DONE (local fallback) |
| 9 | Correlation and risk scoring | DONE |
| 10 | Scan orchestration and scan API | DONE (in-process local mode) |
| 11 | History and dashboard API | DONE (anonymous-session scoped) |
| 12 | PDF and JSON reports | DONE (local file storage) |
| 13 | Frontend foundation and design system | DONE (responsive shell) |
| 14 | Landing, scanner, and results pages | DONE (scanner API connected) |
| 15 | Dashboard, history, and about pages | DONE (session-scoped views) |
| 16 | Frontend test suite and quality gate | NOT STARTED |
| 17 | Security hardening and security tests | NOT STARTED |
| 18 | Backend integration and end-to-end tests | NOT STARTED |
| 19 | Production deployment | NOT STARTED |
| 20 | Final acceptance audit and handover | NOT STARTED |

## Step 0 decisions

| Decision | Value |
|---|---|
| Frontend package manager | npm |
| Python environment | venv |
| Repository visibility | Private initially |
| Intended use | Personal / learning |
| Provider keys | None currently |
| Google Safe Browsing | Decide later |
| Hosting | Vercel + Render |
| Custom domain | None |
| Brand | Specification defaults |
| Scan retention | 30 days |
| Anonymous session TTL | 24 hours |
| Development MOCK providers | Enabled only in development |
| License | MIT assumed for the skeleton; confirm before release |

## Environment variables

No environment variables have been set. Secrets must be supplied locally through ignored `.env` files.

## Open questions and blockers

- Docker, PostgreSQL, Redis, and Celery are intentionally not used for the local simplified mode.
- Local development uses SQLite and reports Redis/worker as unavailable until deployment infrastructure is added.
- Pre-commit could not fetch remote hook repositories because Git could not obtain credentials in this environment.
- Confirm the license before production release.
- Provider licensing and API keys must be reviewed before public deployment.
- The initial SQLite-compatible schema migration is `0001_initial`.
- Indicator validation is enforced by the backend; frontend Zod validation is UX-only.
- Redis policy: fail closed for scan creation, fail open for read-only endpoints.
- Local rate limits: 20 scans/hour/session, 60 requests/minute/IP, 2 concurrent scans/session.
- Security documentation is in `docs/security.md`.
- VirusTotal adapter uses backend-only `VIRUSTOTAL_API_KEY`; tests use an in-memory HTTP transport.
- Additional provider configuration and result semantics are documented in `docs/providers.md`.
- Local cache and quota behavior is documented in `docs/operations.md`.
- Scoring policy is documented in `docs/scoring.md` and uses version `scoring_v1`.
- Frontend foundation uses a responsive React shell with a reusable visual language;
  frontend Vitest has no test files yet and currently reports "No test files found".
- Scanner UI connects to the local API through `VITE_API_BASE_URL` (default
  `http://localhost:8000/api/v1`) and polls owned scans until results are ready.
- Dashboard and history views consume the session-scoped `/dashboard` and
  `/history` endpoints; the About view documents the product model.
