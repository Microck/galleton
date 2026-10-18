# galleton (TypeScript / JavaScript)

Node.js 20+ is required. The package includes ESM JavaScript and TypeScript declarations, with no runtime npm dependencies.

```sh
npm install galleton
```

Run a configured Galleton daemon separately. Installing this SDK does not install or start the daemon. Read its private API token from a protected file; never put it in source code or command arguments.

```ts
import { Galleton } from "galleton";
const sessions = new Galleton({ token: localDaemonApiToken });
const result = await sessions.request("account", configuredUpstreamURL);
```

`connect`, `status`, `list`, `refresh`, `headers`, `capture`, `forget`, and `request` share the language-neutral daemon API. `request` attaches authentication and captures replacement cookies. It returns buffered `ManagedResponse` data and never automatically retries the upstream operation.

`Credentials` accepts `cookies` (`ImportCookie[]`), `cookie_text` and `cookie_format`. `providers()`, `pause(provider, seconds)` and `resume(provider)` list providers and pause or resume their managed requests and renewals. `GalletonError` may carry the daemon codes `upstream_blocked` or `provider_paused` with `retryAt` set.

This is not a browser client. Do not expose the daemon API token to a frontend. See the root Galleton README and SECURITY.md for adapters, setup, and limitations. Provider validity is not guaranteed by the client.
