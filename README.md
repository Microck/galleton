# galleton 0.1.0

A language-independent session-renewal daemon with TypeScript/JavaScript, Python, Go, and Rust clients.

Import authorized credentials once during onboarding. Applications then ask Galleton to make authenticated requests or return current headers. The daemon renews supported sessions, captures replacement cookies/tokens, and persists them across restarts. Provider renewal rules are shared configuration, not language-specific application code. There is no Wallapop-specific implementation.

This is an initial implementation, not a production-proven or independently audited release. See [verification](docs/VERIFICATION.md), [security](SECURITY.md), and the PR's actual CI results before adoption.

## Scope

One Go daemon owns renewal; any language can use its authenticated HTTP/JSON API. No FFI or mandatory Node runtime is needed. A new provider still requires its supported renewal endpoint and response mapping. A token cannot be made permanently valid when its issuer requires reauthentication, revokes it, or enforces an absolute lifetime. Offline machines cannot renew.

This is a single-host, single-trust-domain service. Its local API token controls every profile in its state directory. A multi-tenant application must enforce its own user-to-profile authorization. Do not give the daemon token to a browser or end user.

Included: OAuth refresh-token exchange, custom HTTP renewal adapters, scheduling, encrypted persistence, rotation checkpoints, per-session coordination, managed authenticated requests, SDKs, tests, a disposable provider, an OpenAPI description, and optional startup installers.

## Build and local demo

Use a supported, patched Go release for deployment. The source language/API minimum is Go 1.23, not a recommendation to deploy that old toolchain.

```sh
go build -trimpath -o bin/galleton ./cmd/galleton
go build -trimpath -o bin/demo-provider ./cmd/demo-provider
```

On Windows, build executable names ending in `.exe`. No production binary or registry release is implied by the source version.

Start the disposable provider in one terminal:

```sh
./bin/demo-provider --ttl 10s
```

Start the daemon in another:

```sh
./bin/galleton init --dir ./state
./bin/galleton serve --dir ./state --config ./examples/adapters.demo.json
```

Connect and use the fake accounts in a third terminal:

```sh
./bin/galleton connect --dir ./state demo < examples/credentials.demo.oauth.json
./bin/galleton connect --dir ./state demo-cookie < examples/credentials.demo.cookie.json
./bin/galleton request --dir ./state --url http://127.0.0.1:9909/me demo
./bin/galleton status --dir ./state demo
```

Connect promptly after starting the demo provider: the initial refresh credentials expire after 30 seconds. The adapter renews every two seconds. Restarting only the daemon preserves credentials; restarting the disposable provider resets them and requires an explicit reconnect. The demo credentials are public test data, never production credentials.

CLI flags precede positional IDs. `connect` reads JSON from stdin. Real credentials belong in your onboarding flow or a protected stdin stream, not shell history or committed files.

## Integrate from any language

Install clients from this checkout; none of the package names implies availability on a registry.

### TypeScript / JavaScript

```sh
npm install /absolute/path/to/galleton/sdk/typescript
```

```ts
import { readFile } from "node:fs/promises";
import { Galleton } from "galleton";

const token = (await readFile("./state/api.token", "utf8")).trim();
const sessions = new Galleton({ token });
// During onboarding only: await sessions.connect("account", credentials);
const response = await sessions.request("demo", "http://127.0.0.1:9909/me");
if (!response.ok) throw new Error(`Upstream HTTP ${response.status}`);
console.log(response.json());
```

Node.js 20+ is required. Compiled JavaScript and declarations are included; there are no runtime npm dependencies. The daemon API token is separate from provider credentials and must remain server-side.

### Python

```sh
python -m pip install /absolute/path/to/galleton/sdk/python
```

```python
from galleton import Galleton

sessions = Galleton.from_dir("./state")
response = sessions.request("demo", "http://127.0.0.1:9909/me")
print(response.status, response.json())
```

Python 3.10+; no third-party runtime dependencies. Calls are synchronous.

### Go

From a consuming module, use a checkout until a tagged release is available:

```sh
go mod edit -require=github.com/Microck/galleton@v0.0.0
go mod edit -replace=github.com/Microck/galleton=/absolute/path/to/galleton
go mod tidy
```

Import `github.com/Microck/galleton/client`. After creating a context `ctx`:

```go
sessions, err := client.FromDir("http://127.0.0.1:8766", "./state")
if err != nil { return err }
response, err := sessions.Request(ctx, "demo", "GET",
    "http://127.0.0.1:9909/me", nil, nil)
if err != nil { return err }
// response.Status, response.Headers, response.Body
```

See the complete executable in [examples/go/main.go](examples/go/main.go).

### Rust

```toml
[dependencies]
galleton = { path = "/absolute/path/to/galleton/sdk/rust" }
```

```rust
use std::collections::HashMap;
use galleton::Galleton;

let sessions = Galleton::from_dir("http://127.0.0.1:8766", "./state")?;
let response = sessions.request(
    "demo", "GET", "http://127.0.0.1:9909/me", &HashMap::new(), &[]
)?;
```

The Rust SDK is blocking; use a worker thread in async applications. Its dependencies are declared in Cargo.toml. Check the separate Rust CI job, since Rust was unavailable in the local preparation environment.

### Other languages and existing transports

Use HTTP/JSON at `http://127.0.0.1:8766`, authenticating with `Authorization: Bearer <contents of api.token>`. See [OpenAPI](docs/openapi.json).

All clients expose `connect`, `status`, `list`, `refresh`, `headers`, `capture`, `forget`, and `request`. Managed `request` attaches authentication and persists response cookies before returning. Upstream non-2xx statuses are returned; resource calls are never automatically retried. Requests are limited to 1 MiB bodies and responses to 4 MiB, buffered rather than streamed.

For an existing HTTP transport, obtain `headers(id, url)`, make the request, and pass each separate `Set-Cookie` value to `capture(id, url, values)`. Do not join Set-Cookie lines with commas. You own redirect safety and concurrency in that mode: use managed requests when resource calls can rotate single-use session cookies. Never log returned credential headers.

## Configure a real provider

Start from [examples/adapters.template.json](examples/adapters.template.json), whose endpoints are illustrative, not live integrations. The trusted adapter is read at daemon startup.

```json
{
  "providers": [{
    "name": "my-cookie-provider",
    "kind": "http",
    "origins": ["https://app.example.com"],
    "refresh_url": "https://app.example.com/session/refresh",
    "refresh_method": "GET",
    "response": {"require_set_cookie": true},
    "refresh_interval_seconds": 3600
  }]
}
```

This example assumes the provider actually renews through that endpoint and returns replacement cookies. Set a provider-appropriate interval; one hour is not a universal safe value. Import credentials once through your application:

```json
{
  "provider": "my-cookie-provider",
  "cookie_origin": "https://app.example.com",
  "cookie_header": "session=USER_SUPPLIED_VALUE"
}
```

OAuth adapters use `kind: "oauth2"`, a refresh URL, and a refresh token issued to the registered client. Confidential clients use `client_auth: "basic"` or `"body"` and `client_secret_env`. An access token alone is insufficient. Custom request bodies, CSRF headers, and response fields use restricted templates and JSON pointers; see [adapter reference](docs/ADAPTERS.md).

Changing a provider configuration conservatively blocks its existing sessions until explicit reconnection, including scheduling-only changes in this version. All allowlisted origins are trusted credential destinations; never include unrelated sites.

## Run independently of the application

The daemon must remain running to renew sessions when the main application closes. Startup installation is explicit and optional:

```sh
sh deploy/install-systemd.sh /path/to/galleton /path/to/state /path/to/adapters.json
python3 deploy/install-launchd.py /path/to/galleton /path/to/state /path/to/adapters.json
```

```powershell
.\deploy\install-windows.ps1 -Binary C:\path\galleton.exe -StateDir C:\path\state -Config C:\path\adapters.json
```

Use the installer for your operating system, after initialization and after stopping a manually running daemon. These are user-level jobs, not a guarantee of execution while logged out. See [deployment](deploy/README.md) for service environments, limitations, and uninstall commands. The installers were not executed locally.

## Failure and persistence contract

`retry_wait` applies backoff and honors Retry-After. `storage_error` means a replacement credential has not been durably acknowledged; the daemon retries persistence before another renewal. `reauth_required`, `uncertain`, `configuration_error`, and `protocol_error` stop automatic renewal. Handle them through explicit provider-approved reconnection, using `replace: true`; do not hide them behind endless retries. `forget` removes local state but does not revoke credentials at the provider.

A pending encrypted checkpoint precedes every refresh. Restarting with an unfinished checkpoint becomes `uncertain` rather than replaying a potentially consumed token. This cannot eliminate the distributed failure window between a remote provider and local disk. Metadata exposes errors and deadlines; unknown times may appear as `0001-01-01T00:00:00Z`. There is no push-notification subsystem.

State uses AES-256-GCM, fresh nonces, authenticated session IDs, file replacement, and an exclusive OS lock. Default key and data are co-located; compromise of that directory exposes both. `GALLETON_MASTER_KEY` accepts standard base64 encoding of 32 random bytes supplied before initialization and on every start. There is no automatic encryption-key rotation or keychain integration.

Cookies are exact-origin scoped, including scheme and port. Browser partitioning, SameSite navigation evaluation, device-bound authentication, DPoP/mTLS, and login UI are outside this version. Read [SECURITY.md](SECURITY.md) before retaining real credentials.

## Tests

```sh
go test -race -count=1 -cover ./...
go vet ./...
node --test sdk/typescript/test.mjs
PYTHONPATH=sdk/python python -m unittest discover -s sdk/python -v
python tests/integration.py
npx --yes --package typescript@5.8.3 tsc -p sdk/typescript/tsconfig.json
cargo test --manifest-path sdk/rust/Cargo.toml
```

The integration test uses only disposable loopback credentials and exercises renewal beyond original lifetimes plus daemon restart. GitHub CI separately tests Go on Linux/macOS/Windows, language clients and integration, and Rust. Actual completed results, not merely configured jobs, determine verification status.

Source package names are `galleton`; the executable is `galleton`; environment variables use `GALLETON_`. Nothing has been published to npm, PyPI, or crates.io. Generated distribution archives are not committed. See [rename compatibility](docs/RENAMING.md) for existing encrypted state.
