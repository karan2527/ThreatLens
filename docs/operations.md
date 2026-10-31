# Local operations

The simple development mode uses an in-process provider cache and quota
manager. Cache keys follow:

```text
tl:cache:{provider}:{indicator_type}:{canonical_hash}
```

Successful, skipped, and not-found results may be cached. Failed, timed-out,
rate-limited, and unavailable results are never cached. Not-found results have
a 15-minute TTL so a newly listed indicator is not hidden for long.

The local quota manager uses conservative sliding windows. A deployed version
can replace these stores with Redis without changing provider adapters. Because
the local stores are process-local, do not run multiple API workers against
the same local SQLite database.
