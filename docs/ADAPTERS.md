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

The next refresh is the earliest of the configured interval, an access-token expiry minus its margin, and known cookie expiries minus their margins. No cookie expiry is rewritten into perpetual validity. Imported bare `Cookie` headers do not contain expiry metadata; scheduling uses the interval until a provider response supplies expiry data.

The refresh endpoint and all resource destinations must be allowlisted. Redirects are not followed. Cookies are scoped more narrowly than browser Domain semantics: they remain on the exact issuing origin, even when the server sets a parent `Domain`. Import separately for other approved origins only when that provider actually supports doing so. Bearer access tokens may be sent to any explicitly listed origin; never mix unrelated providers or untrusted destinations in one adapter.

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

Allowed refresh methods are GET and POST. POST bodies are `none` (default), `form`, or `json`. JSON body mappings in this release produce an object of string values; arbitrary nested body construction is not implemented. Cookies are automatically attached when they match the refresh origin/path. Authorization is not automatically attached to a custom refresh request; configure `"Authorization": "Bearer ${access_token}"` only when the endpoint requires it.

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
| `require_set_cookie` | Require at least one accepted, retained replacement cookie. Deletions are honored but are not renewal evidence. It does not prove indefinite authorization. |

A 2xx response alone does not count as renewal. The adapter must receive a configured access token, an accepted cookie update, or a configured successful boolean check. An HTML login page with no such evidence is not treated as successful renewal.

A `Set-Cookie` deletion is accepted and honored, but a deletion alone does not prove that usable credentials were renewed. `Max-Age` becomes a fixed absolute timestamp before persistence; restoring the state cannot reset that countdown. Session cookies without expiry can be retained, but their server-side validity remains provider-controlled. Invalid-domain cookies and invalid `__Host-`/`__Secure-` cookies are discarded. Partitioned cookies are not supported. A profile is limited to 256 cookies.

## Failure and retry details

A pending checkpoint is persisted before transmitting a renewal. New response credentials are persisted before acknowledging success. A local save failure blocks further renewal while the daemon retries the write; it does not pretend the old credential is still current.

HTTP 429 is treated as an explicit rate-limit refusal; Retry-After (seconds or HTTP date) is respected, bounded to 24 hours, along with exponential backoff and jitter. Failures before an upstream connection is obtained (for example DNS/dial/TLS-establishment failures) can retry safely and do not require reimport. Once a connection has been obtained, transport failures and 5xx responses are ambiguous by default and stop automatic replay. `retry_safe: true` opts into replay and changes that behavior. The provider must actually support this; it is not inferred from HTTP method or status.

There is no exactly-once guarantee across a remote server and a local disk. A process crash after a provider consumes a token but before the response is saved can require reauthentication. The package records and reports that ambiguity instead of reusing a potentially consumed credential indefinitely.

For a custom multi-step authentication protocol outside this mapping, add a new audited adapter implementation or supply a trusted service you control exposing the supported renewal contract. The package does not claim arbitrary-web authentication autodiscovery.

## Primary specifications consulted

- RFC 6749, section 6: OAuth refresh-token exchange.
- RFC 9700, section 4.14: refresh-token rotation and replay considerations.
- RFC 6265: Cookie/Set-Cookie semantics; Galleton deliberately narrows origin scope.
- RFC 6901: JSON pointers.
- Go standard-library documentation for `crypto/cipher`, `net/http`, and `net/http/cookiejar`.
