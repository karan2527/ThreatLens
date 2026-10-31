# Alembic migrations

ThreatLens uses Alembic for all schema changes. The local development database is
SQLite; deployment can provide a PostgreSQL `DATABASE_URL`.

Run the initial migration from `backend/`:

```bash
.venv/bin/alembic upgrade head
```

Inspect the current revision:

```bash
.venv/bin/alembic current
```

Never edit a deployed database manually. Add a new migration for every schema
change.
