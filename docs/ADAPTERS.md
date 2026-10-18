# Adapter reference

Provider configurations are trusted, startup-time operator data. The local API cannot install or modify an adapter.

## Common fields

| Field | Meaning |
|---|---|
| `name` | 1–64 ASCII letters, digits, `_`, or `-`. |
| `kind` | `oauth2` or `http`. |
| `origins` | Exact HTTP(S) origins, including nondefault ports. No paths, query, wildcards, URL credentials, or fragments. All listed origins are trusted credential destinations. |
| `refresh_url` | Absolute URL on one of those origins. Keep secrets out of the URL. |
| `refresh_interval_seconds` | Required, 1–2592000. Upper bound between successful renewals, not an override of token lifetime. |
| `refresh_before_seconds` | Default 60. Proactive expiry margin, capped at 20% of the remaining lifetime for short-lived tokens/cookies. |
| `timeout_seconds` | Default 20, range 1–120, per upstream operation. |
| `retry_safe` | Default false. Explicitly permits retrying ambiguous network/5xx refresh failures. Use only when the provider's refresh operation safely permits replay. Being an HTTP GET alone is not proof. |
| `allow_http_loopback` | Default false. Allows HTTP only on literal loopback IPs for local development. Never enables plaintext Internet endpoints. |

Optional per-provider fields, described in [Provider options](#provider-options):

| Field | Meaning |
|---|---|
| `cookie_domain` | A domain such as `.www.example.com`. Cookies the provider sets for exactly that domain match every listed origin inside it, and no others. |
| `protected_cookies` | Cookie names that only a successful renewal may set. Managed responses and `/cookies` captures cannot replace them. |
| `proxy` / `proxy_env` | Egress proxy: `http`, `https`, `socks5` or `socks5h`. Fails closed; never falls back to a direct connection. |
| `block_signatures` | Bot-protection responses that mean "try later", not "log in again". |
| `min_interval_ms` | Minimum gap between upstream calls of this provider, renewals and managed requests together. |
| `keep_alive` | Reuse connections for managed requests. Renewals always use a fresh connection. |
| `max_request_body_bytes` / `max_response_body_bytes` | Managed request limits. Defaults 1 MiB and 4 MiB, at most 64 MiB each. |

The next refresh is the earliest of the configured interval, an access-token expiry minus its margin, and known cookie expiries minus their margins. No cookie expiry is rewritten into perpetual validity. Imported bare `Cookie` headers do not contain expiry metadata; scheduling uses the interval until a provider response supplies expiry data.

The refresh endpoint and all resource destinations must be allowlisted. Redirects are not followed. Cookies are scoped more narrowly than browser Domain semantics: they remain on the exact issuing origin, even when the server sets a parent `Domain`, unless that `Domain` equals the adapter's declared `cookie_domain`. Bearer access tokens may be sent to any explicitly listed origin; never mix unrelated providers or untrusted destinations in one adapter.

A change to any field invalidates sessions imported under the old configuration (`configuration_error`), with one exception: `proxy`, `proxy_env`, `keep_alive`, `min_interval_ms`, `max_request_body_bytes`, `max_response_body_bytes` and `block_signatures` describe egress and pacing, not what a credential means or where it may go, so changing them keeps existing sessions.

## Standard OAuth refresh

```json
{
  "name": "provider",
  "kind": "oauth2",
  "origins": ["https://auth.example.com", "https://api.example.com"],
  "refresh_url": "https://auth.example.com/oauth/token",
  "client_id": "REGISTERED_CLIENT_ID",
  "client_auth": "basic",
  "client_secret_env": "PROVIDER_CLIENT_SECRET",
  "refresh_interval_seconds": 900
}
```

`client_auth` is `none` (default), `basic`, or `body`. Basic/body modes require a client ID and nonempty environment-supplied client secret. The request uses `grant_type=refresh_token` and the latest saved refresh token. The daemon does not implement authorization-code login or acquire a refresh token from an arbitrary cookie.

The response must include nonempty `access_token` and `token_type: "Bearer"`. A supplied `refresh_token` replaces the old one; an omitted one preserves the old one. Optional `expires_in` must be a positive integer number of seconds, at most one year; a numeric string is accepted. When absent, renewal follows the configured interval rather than inventing a token expiry.

`invalid_grant` requires reauthentication. `invalid_client`/`unauthorized_client` blocks the client configuration. DPoP, mTLS, and other sender-constrained token types are not supported.

## Custom HTTP renewal

```json
{
  "name": "custom-provider",
  "kind": "http",
  "origins": ["https://app.example.com"],
  "refresh_url": "https://app.example.com/session/refresh",
  "refresh_method": "POST",
  "refresh_headers": {
    "X-CSRF-Token": "${cookie.csrf}",
    "X-Application": "my-app"
  },
  "body_format": "json",
  "body": { "refresh": "${refresh_token}" },
  "response": {
    "access_token_pointer": "/data/accessToken",
    "refresh_token_pointer": "/data/refreshToken",
    "expires_in_pointer": "/data/expiresIn",
    "success_pointer": "/ok"
  },
  "refresh_interval_seconds": 1800
}
```

Allowed refresh methods are GET and POST. POST bodies are `none` (default), `form`, or `json`. JSON body mappings in this release produce an object of string values; arbitrary nested body construction is not implemented. With `body_format: "json"` and no `body`, the request body is exactly `{}` with `Content-Type: application/json`. Cookies are automatically attached when they match the refresh origin/path. Authorization is not automatically attached to a custom refresh request; configure `"Authorization": "Bearer ${access_token}"` only when the endpoint requires it.

Templates are limited string substitution:

- `${access_token}` / `${refresh_token}`: the current saved value.
- `${secret.NAME}`: a named secret supplied at import.
- `${cookie.NAME}`: the first cookie of that name matching the refresh URL.

Missing variables fail before sending any request. Variables are not available in URLs, and no scripts, shell commands, JavaScript expressions, or arbitrary code are evaluated. Headers that change connection routing/framing are rejected.

Response selectors use RFC 6901 JSON pointers, not JSONPath. `/data/tokens/0/value` selects nested object/array values; `~0` escapes `~` and `~1` escapes `/`.

| Response field | Behavior |
|---|---|
| `access_token_pointer` | When configured, must select a nonempty string. |
| `refresh_token_pointer` | A present, valid value replaces the old token; absence preserves it. |
| `expires_in_pointer` | Optional positive integer seconds. If the field is absent, no expiry is invented. |
| `expires_at_pointer` | When configured, must select a future RFC3339 time string. |
| `success_pointer` | When configured, must select the JSON boolean `true`. |
| `require_set_cookie` | Require at least one accepted, retained replacement cookie. With `protected_cookies`, every protected cookie the session holds must be replaced too. Deletions are honored but are not renewal evidence. It does not prove indefinite authorization. |

A 2xx response alone does not count as renewal. The adapter must receive a configured access token, an accepted cookie update, or a configured successful boolean check. An HTML login page with no such evidence is not treated as successful renewal.

Every configured proof is required, not just one. When a provider rotates single-use credentials in `Set-Cookie` (Vinted does), list them in `protected_cookies` and set `require_set_cookie: true`. A response that replaces only an unrelated cookie (a bot-protection cookie, say) then stops as `protocol_error` instead of keeping a stale refresh cookie that the next renewal would replay. When the JSON body rotates a token too, configure its pointer as well.

A `Set-Cookie` deletion is accepted and honored, but a deletion alone does not prove that usable credentials were renewed. `Max-Age` becomes a fixed absolute timestamp before persistence; restoring the state cannot reset that countdown. Session cookies without expiry can be retained, but their server-side validity remains provider-controlled. Invalid-domain cookies and invalid `__Host-`/`__Secure-` cookies are discarded. Partitioned cookies are not supported. A profile is limited to 256 cookies.

## Provider options

### Cookie domain

`cookie_domain` declares the one domain whose cookies the session shares across origins, for example `.www.vinted.com` for `www.vinted.com` and `api.www.vinted.com`. It must have at least two labels and contain at least one listed origin. RFC 6265 domain matching then applies only within the allowlist:

- A `Set-Cookie` with `Domain` equal to `cookie_domain` is stored once and sent to every listed origin whose host is that domain or a subdomain of it. Unlisted hosts never receive it.
- A `Set-Cookie` with any other parent `Domain` (such as `.vinted.com`) is still narrowed to the exact issuing origin.
- A scoped cookie replaces host-only copies of the same name and path inside its domain, so a rotated token cannot be shadowed by the imported one.
- A bare `Cookie` header imported for an origin inside `cookie_domain` is scoped to it, because the header carries no scope of its own.

### Protected cookies

`protected_cookies` lists credential cookies that only a successful (2xx) renewal response may set or delete. `Set-Cookie` values for those names from managed responses, `/cookies` captures, and non-2xx renewal responses are ignored. Ignoring them is not an error, so a server-rendered page that hands out guest tokens does not overwrite or pause the real session. With `require_set_cookie`, a successful renewal must replace every protected cookie the session still holds (see above).

### Egress proxy

`proxy` routes every upstream call of the provider (renewals and managed requests) through one proxy: `http://`, `https://`, `socks5://` or `socks5h://`, with an explicit port for SOCKS. Both SOCKS schemes send the host name to the proxy; the daemon does not resolve provider names locally. Proxy credentials are rejected in the configuration file. Put a credentialed URL in an environment variable and name it with `proxy_env`; startup fails when that variable is missing.

The proxy is the only route. Environment proxy variables are ignored, and when the proxy refuses or cannot be reached, the call fails before any credential leaves; a renewal waits for backoff (`retry_later`). There is no direct-connection fallback. The proxy URL never appears in errors, logs or the provider listing, which only reports `"proxied": true`.

### Block signatures

Bot-protection layers answer with a challenge page while the credential is still valid. `block_signatures` lets an adapter recognize those responses:

```json
"block_signatures": [
  {"status": [403], "body_contains": "captcha-delivery.com"},
  {"status": [403, 503], "header": "Cf-Mitigated", "header_contains": "challenge"},
  {"status": [403], "not_json": true}
]
```

A signature matches when the status is listed and every configured matcher holds: `body_contains` (a substring of the response body), `header` (present) with optional `header_contains`, and `not_json` (the body is not a JSON document, so it is not the provider's own error). Status codes must be 400–599 and never 401, and each signature needs at least one matcher besides the status, so a real revocation is not hidden.

A matching renewal response becomes `upstream_blocked`: the session moves to `retry_wait` with exponential backoff, `Retry-After` is honored (bounded to 24 hours), credentials are kept, and protected cookies in the response are ignored. Clients keep receiving still-valid credentials meanwhile. HTTP 401 and OAuth `invalid_grant` remain `reauth_required` even when a signature would match. A 403 that matches no signature also remains `reauth_required`.

### Pacing and pause

`min_interval_ms` (0–3600000) spaces upstream calls of one provider across all of its sessions, counting renewals and managed requests together. The gap is measured from when the previous call actually left, after its checkpoint was written, so a call delayed after taking its turn cannot crowd the next one. A call that would wait longer than `timeout_seconds` is refused with `retry_later` and a `retry_at` instead; a deferred renewal keeps serving still-valid credentials. The schedule lives in memory.

Any client holding the API token can pause a provider, for example after its own requests hit a block:

```http
POST /v1/providers/vinted/pause
{"seconds": 900}

DELETE /v1/providers/vinted/pause
```

While paused, managed requests fail with `provider_paused` and a `retry_at`, the scheduler starts no renewals, and `/headers` serves still-valid credentials without renewing. A call that was already waiting for its turn when the pause was set is refused too, before anything is sent. A pause only extends an existing one (1–86400 seconds per call). It is saved encrypted in the state directory, so a daemon restart keeps it; if saving fails the pause still applies and the call reports `storage_failure`. `GET /v1/providers` shows `paused_until`.

### Keep-alive

`keep_alive: true` pools connections for managed requests. Renewals always open a fresh connection, so the transport can never resend a rotating credential on a stale pooled connection. On a pooled connection, Go resends a managed request only when nothing was written yet, or for idempotent requests (GET, HEAD, OPTIONS, or requests carrying an `Idempotency-Key` header) when the server closed the reused connection without answering.

### Managed request limits

`max_request_body_bytes` and `max_response_body_bytes` raise or lower the buffered managed request limits (defaults 1 MiB and 4 MiB, at most 64 MiB each). The daemon sizes the `/request` API body limit to the largest adapter limit in base64. Bodies are still buffered in memory; this is not streaming. Base64 and JSON encoding mean one in-flight call can hold about four times its body limit in memory, and calls of different sessions run concurrently, so size the limits to the host.

## Cookie imports

`connect` accepts cookies in these shapes. All of them are filtered through the provider allowlist: cookies for domains outside every listed origin are skipped, so a whole-browser export imports only what this provider may use.

| Input | API field | Notes |
|---|---|---|
| `Cookie:` header or `a=b; c=d` | `cookie_header` | No scope or expiry. Stored for `cookie_origin` (or `cookie_domain`, see above). |
| `Set-Cookie` values | `set_cookies` | Attributes are kept. Lines without `Domain` belong to `cookie_origin`. |
| Structured cookies | `cookies` | `{name, value, domain, host_only, path, expires, secure, http_only, same_site}`. |

A host-only cookie is stored for each listed origin on that host. A domain cookie equal to `cookie_domain` keeps that scope; other domain cookies are copied host-only onto each listed origin inside the domain. A `__Host-` cookie that names a domain is rejected. When several fields are supplied, later ones win: `cookie_header`, then `set_cookies`, then `cookies`.

The daemon does not parse browser export files. The CLI does, locally, and sends structured `cookies`; the Go package `github.com/Microck/galleton/cookiefile` exposes the same parser. It reads, up to 16 MiB and 4096 cookies:

- Netscape `cookies.txt`: tab-separated, `#HttpOnly_` lines set HttpOnly, expiry 0 is a session cookie
- Cookie-Editor or EditThisCookie JSON, as an array or a `{"url": ..., "cookies": [...]}` wrapper: `hostOnly`, `expirationDate` and `sameSite` are honored, and the wrapper's URL supplies a missing domain. DevTools and Playwright cookie lists have the same shape: without `hostOnly`, a leading dot marks a domain cookie, and `expires: -1` is a session cookie
- a `Cookie:` header or `a=b; c=d`

```sh
galleton connect --provider vinted --cookies ./cookies.txt account
galleton connect --provider vinted --cookies ./cookies.json --format json account
galleton connect --provider vinted --cookies - --cookie-origin https://www.vinted.com account < cookie-header.txt
```

`--credentials FILE` merges a credentials JSON object (for tokens or secrets), and `--replace --expected-revision N` reconnects an existing session.

## Example: Vinted web session

[`examples/adapters.vinted.json`](../examples/adapters.vinted.json) configures `www.vinted.com` and `api.www.vinted.com`:

- renewal is `POST https://www.vinted.com/web/api/auth/refresh` with body `{}` and the session cookies attached
- the response must rotate cookies (`require_set_cookie`), including both protected ones, and sets the expiry from `/expires_in`. No access-token pointer is configured, so requests stay cookie-based like the website and carry no `Authorization` header
- `cookie_domain` is `.www.vinted.com`, so rotated `access_token_web`/`refresh_token_web` reach both hosts; `datadome` and `__cf_bm`, set on `.vinted.com`, stay on the origin that received them
- `access_token_web` and `refresh_token_web` are protected: a catalog page handing out guest tokens cannot replace them, and a renewal that does not replace both stops instead of replaying a spent refresh cookie
- DataDome and Cloudflare challenge pages, and any non-JSON 403, are temporary refusals
- requests are spaced by at least one second, pooled, and allowed 32 MiB uploads and 8 MiB pages

Each country is its own origin and cookie domain (`www.vinted.fr`, `www.vinted.es`, ...): add one provider per country. Add `proxy_env` when renewals must leave through the same egress as the application. Vinted's `refresh_token_web` is single-use and replaying an old one revokes the session, so the daemon must be the only party renewing it; the application should stop running its own refresh.

## Failure and retry details

A pending checkpoint is persisted before transmitting a renewal. New response credentials are persisted before acknowledging success. A local save failure blocks further renewal while the daemon retries the write; it does not pretend the old credential is still current.

HTTP 429 is treated as an explicit rate-limit refusal; Retry-After (seconds or HTTP date) is respected, bounded to 24 hours, along with exponential backoff and jitter. A response matching a configured block signature is handled the same way and reported as `upstream_blocked`. Failures before an upstream connection is obtained (for example DNS/dial/TLS-establishment failures, or an unreachable proxy) can retry safely and do not require reimport. Once a connection has been obtained, transport failures and 5xx responses are ambiguous by default and stop automatic replay. `retry_safe: true` opts into replay and changes that behavior. The provider must actually support this; it is not inferred from HTTP method or status.

There is no exactly-once guarantee across a remote server and a local disk. A process crash after a provider consumes a token but before the response is saved can require reauthentication. The package records and reports that ambiguity instead of reusing a potentially consumed credential indefinitely.

For a custom multi-step authentication protocol outside this mapping, add a new audited adapter implementation or supply a trusted service you control exposing the supported renewal contract. The package does not claim arbitrary-web authentication autodiscovery.

## Primary specifications consulted

- RFC 6749, section 6: OAuth refresh-token exchange.
- RFC 9700, section 4.14: refresh-token rotation and replay considerations.
- RFC 6265: Cookie/Set-Cookie semantics; Galleton deliberately narrows origin scope, and applies section 5.1.3 domain matching only for a declared `cookie_domain` within the allowlist.
- RFC 1928: SOCKS version 5.
- RFC 6901: JSON pointers.
- Go standard-library documentation for `crypto/cipher`, `net/http`, and `net/http/cookiejar`.
