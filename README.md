<p align="center">
  <img src="https://litter.catbox.moe/cwz7k3o9ywknb7td.png" alt="galleton" width="240">
</p>

<p align="center">
  <a href="https://github.com/Microck/galleton"><img src="https://img.shields.io/badge/source-github-000000?style=flat-square" alt="source"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-see%20file-000000?style=flat-square" alt="license"></a>
</p>

---

`galleton` is a language-independent session-renewal daemon. it lets applications in TypeScript/JavaScript, Python, Go, Rust, or any language that can use HTTP/JSON make authenticated requests after you import authorized credentials once. the daemon renews supported sessions, stores rotated credentials, and keeps provider rules out of application code.

## why

- one Go daemon serves clients written in any language
- OAuth refresh and configured HTTP renewal adapters share one service
- encrypted local storage persists credentials and rotation checkpoints
- managed requests coordinate per-session use and save response cookies
- no FFI or mandatory Node.js runtime

the daemon cannot extend a provider's token lifetime or bypass revocation, reauthentication, or provider limits. it is a single-host, single-trust-domain service, not a multi-tenant authorization layer.

## start here

build the daemon and disposable demo provider with Go:

```sh
go build -trimpath -o bin/galleton ./cmd/galleton
go build -trimpath -o bin/demo-provider ./cmd/demo-provider
```

run the demo provider in one terminal:

```sh
./bin/demo-provider --ttl 10s
```

start the daemon in another:

```sh
./bin/galleton init --dir ./state
./bin/galleton serve --dir ./state --config ./examples/adapters.demo.json
```

connect a disposable account and make a managed request in a third:

```sh
./bin/galleton connect --dir ./state demo < examples/credentials.demo.oauth.json
./bin/galleton request --dir ./state --url http://127.0.0.1:9909/me demo
./bin/galleton status --dir ./state demo
```

connect promptly after starting the demo provider. its initial refresh credentials expire after 30 seconds. demo credentials are public test data, never production credentials.

## clients

the SDKs are available in this repository. install them from a local checkout:

| language | path | requirements |
| --- | --- | --- |
| TypeScript / JavaScript | `sdk/typescript` | Node.js 20+ |
| Python | `sdk/python` | Python 3.10+ |
| Go | `client` | Go 1.23+ source/API minimum |
| Rust | `sdk/rust` | see `sdk/rust/Cargo.toml` |
| other languages | HTTP/JSON API | see [OpenAPI](docs/openapi.json) |

for example, install the TypeScript SDK:

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

the daemon API token grants access to every profile in its state directory. keep it server-side; do not expose it to browsers or end users.

## configure a provider

start with [the adapter template](examples/adapters.template.json). its endpoints are examples, not live integrations. configure only provider-approved renewal endpoints and allowlist only the exact trusted origins that need credential access.

cookie adapters require an endpoint that returns replacement `Set-Cookie` values. for OAuth adapters, a refresh token issued for the registered client is required; an access token alone is not enough. see the [adapter reference](docs/ADAPTERS.md) for supported fields and templates.

import real credentials through a protected onboarding flow or stdin. do not put them in shell history, committed files, or logs.

## security and limits

the daemon binds to literal loopback addresses and requires a local bearer token. it encrypts stored credentials with AES-256-GCM. the default key and data are stored together, so restrict the state directory to its owning OS user. the daemon token has administrator-level access to all profiles.

managed requests are buffered, limited to 1 MiB request bodies and 4 MiB responses, and are not automatically retried. restarting with an unfinished rotation checkpoint pauses that session for review instead of replaying a potentially consumed token. the daemon does not provide multi-tenant access control, streaming, browser-equivalent cookie behavior, or protection from other local processes running as the same user.

see [SECURITY.md](SECURITY.md) for the full security model and limitations.

## tests

```sh
make test
make integration
cargo test --manifest-path sdk/rust/Cargo.toml
```

## documentation

- [adapter reference](docs/ADAPTERS.md)
- [deployment and startup installers](deploy/README.md)
- [OpenAPI description](docs/openapi.json)
- [security model](SECURITY.md)
- [verification status](docs/VERIFICATION.md)

## license

see [LICENSE](LICENSE).
