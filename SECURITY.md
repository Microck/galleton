# Security model and release status

Galleton 0.1.0 is a new implementation. Local tests are not a security audit, production operating history, or proof of compatibility with any live service. No real user credentials were used during verification.

## Intended use

Use only credentials the account holder has authorized the application to retain and renew. Provider expiry, revocation, challenge responses, and unsupported token-binding mechanisms are respected. There is no browser-cookie harvesting, CAPTCHA handling, fingerprint impersonation, login bypass, or forced extension of server-side session lifetime.

One state directory belongs to one trusted application/OS-user boundary. A local API token has administrator-equivalent access to every profile in that daemon. The API does not enforce per-profile access control. A public or multi-tenant backend needs its own authorization layer and must never forward its daemon token to end users.

## Implemented protections

The listener is restricted to literal loopback IPs. Every endpoint requires the local bearer token. Browser Origin/fetch-metadata requests are denied, CORS is not enabled, and literal loopback Host validation limits DNS-rebinding access. This is not a defense against malicious code already running as the same OS user.

Trusted provider configuration restricts upstream origins. HTTPS and certificate verification are required except explicitly enabled loopback HTTP test providers. Credentials are not sent through environment proxies, redirects, arbitrary URL templates, or a client-supplied Host header. The daemon's own API token is not forwarded upstream.

An adapter may opt into one explicit egress proxy (`http`, `https`, `socks5`, `socks5h`). It is then the only route for that provider: when the proxy is unreachable or refuses, the call fails, and nothing is retried over a direct connection. A proxy sees the destination host, and for plain-HTTP loopback test providers the full request. Proxy credentials are accepted only through an environment variable named by `proxy_env`, never in the configuration file; the proxy URL is not logged and not returned by the API. A missing proxy variable stops startup instead of disabling the proxy.

Cookie scope stays tied to the allowlist. An adapter-declared `cookie_domain` shares cookies set for exactly that domain among listed origins inside it; no unlisted host receives them, and other parent-domain cookies are still narrowed to the issuing origin. `protected_cookies` can only be replaced by a successful renewal response, so a managed request that lands on a guest page cannot overwrite session tokens. `jwt_subject_cookie` compares the unverified JWT `sub` claim with the imported one; it detects a swapped account, it does not authenticate the token. The recorded subject is stored encrypted and is not returned by the API.

Block signatures and pacing exist so a bot-protection challenge is not misread as a revoked credential and so the daemon's traffic can be spaced and paused with the application's. They do not solve challenges, change fingerprints, or evade bot protection. Signatures cannot match HTTP 401 or OAuth `invalid_grant`, and each needs a body or header marker beyond the status code, so a real revocation still requires reconnection.

Credentials are encrypted using standard-library AES-256-GCM with a fresh random nonce and the session ID as authenticated data. Keys are random, not password-derived. Credential values and upstream response bodies are not logged. API responses are marked `no-store`. Token/header retrieval intentionally returns usable access credentials to an authorized local client.

On Unix, state directories/files use mode 0700/0600. Windows file access relies on the directory's actual Windows ACLs; POSIX mode bits alone do not establish equivalent protection. Keep state under a directory restricted to the owning user.

OS file locks exclude a second writer. Per-profile locks serialize renewal and managed resource calls. Rotation checkpoints, local-write retry behavior, and conservative handling of lost responses reduce accidental refresh-token reuse. They do not solve the distributed exactly-once problem.

## Limitations requiring explicit acceptance

- Default key and encrypted state are co-located. Losing that directory loses both; compromising it exposes both. Use external master-key injection for a separately protected key. There is no built-in keychain, HSM, key-rotation, memory-zeroization, or password-encrypted vault feature.
- Backups can contain usable credentials. Restoring old state may restore a consumed refresh token; no anti-rollback hardware counter or provider reconciliation protocol exists.
- Atomic replacement/directory synchronization was exercised locally on Linux, not under physical power-loss conditions. See actual CI results for additional platform execution. Storage guarantees depend on the OS/filesystem; network/shared filesystems are unsupported.
- Multiple machines, replicated daemons, uncoordinated browser use of single-use tokens, and other tools independently refreshing the same credentials can break rotation. The daemon must be the single owner of its imported renewal credentials.
- Bare Cookie imports lack Domain/Path/expiry metadata. Their default is root-path, exact-origin scoping, or the adapter's `cookie_domain` when the origin is inside it. Import a structured export (cookies.txt, Cookie-Editor JSON, HAR, Set-Cookie values) when those details matter.
- Cookie exports often contain a whole browser profile. Only cookies for listed origins are stored, but the export file itself stays sensitive; delete it after import.
- Cookies are not browser-equivalent: parent-domain sharing beyond one declared `cookie_domain`, partitioned-cookie context, SameSite navigation evaluation, browser storage, and device-bound authentication are not implemented.
- Managed requests are buffered, not streaming, and the daemon never retries them. Adapters may raise buffering to 64 MiB per request and response, which costs that much memory per in-flight call. With `keep_alive`, Go's transport may resend an idempotent request (GET, HEAD, OPTIONS, or one carrying `Idempotency-Key`) once when the server closed a reused connection without answering. Renewals never use pooled connections. Streaming downloads, WebSockets, and browser automation are outside this release.
- Provider pauses and the pacing schedule live in memory. A daemon restart clears them.
- A malformed response may contain a replacement refresh credential but not a usable access token. A parseable replacement is retained, and the session is blocked for adapter review instead of discarding it.
- The Rust SDK was not compiled in the local preparation environment. Check its actual CI result. User-startup installers were supplied but not executed; their presence is not evidence of operational validation.
- Local tests used an older installed Go toolchain. Build deployment binaries using a currently supported and patched release and perform dependency/security review on the target platform.

## Handling terminal states

`reauth_required`, `uncertain`, `configuration_error`, and `protocol_error` stop automatic renewal. Do not turn these into an infinite retry loop. Use provider-approved reconnection with new credentials and the explicit `replace` flag. An uncertain request may already have completed remotely.

When reporting a defect, include the error code, non-secret metadata, operating system, and a synthetic reproduction. Never include cookies, refresh tokens, API tokens, master keys, or decrypted vault state in issue reports.

A dedicated private security-reporting channel has not been configured by this source change. Do not publish sensitive reports or real credentials in public issues; arrange a private channel with the repository owner first.
