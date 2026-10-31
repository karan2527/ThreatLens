# Local security behavior

ThreatLens never stores the raw anonymous session cookie. It stores an
HMAC-SHA256 digest derived from `SECRET_KEY`. Cookies are `HttpOnly`, use
`SameSite=Lax`, and become `Secure` in production.

State-changing requests must include `X-Requested-With`. Requests without it
receive `CSRF_REQUIRED`.

The simple local setup has no Redis. It uses an in-process limiter with these
limits:

- 60 requests per minute per client key
- 20 scans per hour per session
- 2 concurrent scans per session

When Redis is introduced for deployment, scan creation will fail closed if the
limiter is unavailable, while read-only endpoints may continue. Local
development is intentionally single-process, so its limiter is not suitable
for multiple workers.

Logs redact API keys, cookies, authorization values, and session tokens.
