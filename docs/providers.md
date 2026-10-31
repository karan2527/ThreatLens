# Provider configuration

Provider API keys belong only in `backend/.env`, which is ignored by Git.
Adapters never return keys in normalized results.

## URLhaus

The current URLhaus documentation requires an Auth-Key from the abuse.ch
Authentication Portal. The adapter sends it in the `Auth-Key` request header
and uses the v1 lookup endpoints for URL, host, and supported payload lookups.
It never opens the submitted URL.

## Result semantics

- Missing credentials produce `SKIPPED` with `NO_API_KEY`.
- Wrong indicator types produce `SKIPPED` with `NOT_APPLICABLE`.
- URLhaus `no_results` produces `NOT_FOUND`, not `CLEAN`.
- Safe Browsing with no matches produces `UNKNOWN`, not `CLEAN`.
- Provider failures, timeouts, and rate limits are never treated as clean.

Real provider calls should be used sparingly because free-tier quotas and
provider terms vary. Automated tests use mocked HTTP transports.
