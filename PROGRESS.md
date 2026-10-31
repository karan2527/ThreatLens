# ThreatLens Progress

## Step status

| Step | Title | Status |
|---:|---|---|
| 0 | Pre-flight questions and decisions | DONE |
| 1 | Repository, tooling and project skeleton | DONE |
| 2 | Docker Compose, configuration and health endpoint | BLOCKED |
| 3 | Database models and Alembic migrations | NOT STARTED |
| 4 | Indicator validation and normalization | NOT STARTED |
| 5 | Core security layer | NOT STARTED |
| 6 | Provider framework and VirusTotal adapter | NOT STARTED |
| 7 | Additional provider adapters | NOT STARTED |
| 8 | Caching and provider quota management | NOT STARTED |
| 9 | Correlation and risk scoring | NOT STARTED |
| 10 | Scan orchestration and scan API | NOT STARTED |
| 11 | History and dashboard API | NOT STARTED |
| 12 | PDF and JSON reports | NOT STARTED |
| 13 | Frontend foundation and design system | NOT STARTED |
| 14 | Landing, scanner, and results pages | NOT STARTED |
| 15 | Dashboard, history, and about pages | NOT STARTED |
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

- Docker Engine and Docker Compose are not installed in the current environment; Step 2 cannot be verified until they are available.
- Confirm the license before production release.
- Provider licensing and API keys must be reviewed before public deployment.
