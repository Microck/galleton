<p align="center">
  <img src="https://litter.catbox.moe/cwz7k3o9ywknb7td.png" alt="galleton" width="240">
</p>

<p align="center">
  <a href="https://github.com/Microck/galleton"><img src="https://img.shields.io/badge/source-github-000000?style=flat-square" alt="source"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-see%20file-000000?style=flat-square" alt="license"></a>
</p>

---

`galleton` is a language-independent session-renewal daemon. Import authorized credentials once, then let applications in TypeScript/JavaScript, Python, Go, Rust, or any language that can use HTTP/JSON request authenticated resources. The daemon renews supported sessions, stores rotated credentials, and keeps provider rules out of application code.

This is an initial implementation, not a production-proven or independently audited release. Read [verification](docs/VERIFICATION.md) and [security](SECURITY.md) before using real credentials.

## why

- one Go daemon serves clients written in any language
- OAuth refresh and configured HTTP renewal adapters share one service
- encrypted local storage persists credentials and rotation checkpoints
- managed requests coordinate per-session use and save response cookies
- no FFI or mandatory Node.js runtime

Galleton cannot extend a provider's token lifetime or bypass revocation, reauthentication, or provider limits. It is a single-host, single-trust-domain service, not a multi-tenant authorization layer.

## start here

Install Go, then build the daemon and disposable demo provider:

```sh
go build -trimpath -o bin/galleton ./cmd/galleton
go build -trimpath -o bin/demo-provider ./cmd/demo-provider
```

Start the demo provider in one terminal:

```sh
./bin/demo-provider --ttl 10s
```

Start the daemon in another:

```sh
./bin/galleton init --dir ./state
./bin/galleton serve --dir ./state --config ./examples/adapters.demo.json
```

Connect a disposable account and make a managed request in a third:

```sh
./bin/galleton connect --dir ./state demo < examples/credentials.demo.oauth.json
./bin/galleton request --dir ./state --url http://127.0.0.1:9909/me demo
./bin/galleton status --dir ./state demo
```

Connect promptly after starting the demo provider. Its initial refresh credentials expire after 30 seconds. Demo credentials are public test data, never production credentials.

## clients

Client SDKs are included in this checkout. Package names do not imply that they are published to a registry.

| language | path | requirements |
| --- | --- | --- |
| TypeScript / JavaScript | `sdk/typescript` | Node.js 20+ |
| Python | `sdk/python` | Python 3.10+ |
| Go | `client` | Go 1.23+ source/API minimum |
| Rust | `sdk/rust` | see `sdk/rust/Cargo.toml` |
| Other languages | HTTP/JSON API | see [OpenAPI](docs/openapi.json) |

For example, install the TypeScript SDK from a local checkout:

```sh
npm install /absolute/path/to/galleton/sdk/typescript
```

```ts
import { readFile } from "node:fs/promises";
import { Galleton } from "galleton";

const token = (await readFile("./state/api.token", "utf8")).trim();
const sessions = new Galleton({ token });
const response = await sessions.request("demo", "http://127.0.0.1:9909/me");
if (!response.ok) throw new Error(`Upstream HTTP ${response.status}`);
console.log(response.json());
```

The daemon API token grants access to every profile in its state directory. Keep it server-side; do not expose it to browsers or end users.

## configure a provider

Start with [the adapter template](examples/adapters.template.json). Its endpoints are examples, not live integrations. Configure only provider-approved renewal endpoints and allowlist only the exact trusted origins that need credential access.

Cookie adapters require an endpoint that returns replacement `Set-Cookie` values. OAuth adapters require a refresh token issued for the registered client; an access token alone is not enough. See the [adapter reference](docs/ADAPTERS.md) for supported fields and templates.

Import real credentials through a protected onboarding flow or stdin. Do not put them in shell history, committed files, or logs.

## security and limits

The daemon binds to literal loopback addresses and requires a local bearer token. It encrypts stored credentials with AES-256-GCM. The default key and data are stored together, so restrict the state directory to its owning OS user. The daemon token has administrator-level access to all profiles.

Managed requests are buffered, limited to 1 MiB request bodies and 4 MiB responses, and are not automatically retried. Restarting with an unfinished rotation checkpoint pauses that session for review instead of replaying a potentially consumed token. The daemon does not provide multi-tenant access control, streaming, browser-equivalent cookie behavior, or protection from other local processes running as the same user.

See [SECURITY.md](SECURITY.md) for the full security model and limitations.

## tests

```sh
make test
make integration
```

The Rust SDK has a separate test command:

```sh
cargo test --manifest-path sdk/rust/Cargo.toml
```

Configured CI jobs are not proof that a run passed. Check the actual workflow results and [verification notes](docs/VERIFICATION.md).

## documentation

- [adapter reference](docs/ADAPTERS.md)
- [deployment and startup installers](deploy/README.md)
- [OpenAPI description](docs/openapi.json)
- [security model](SECURITY.md)
- [verification status](docs/VERIFICATION.md)

## license

See [LICENSE](LICENSE).
