# galleton (TypeScript / JavaScript)

Local source distribution, not a published npm package. Node.js 20+ or another compatible server-side runtime with fetch is required. Built JavaScript and TypeScript declarations are included; there are no runtime npm dependencies.

```ts
import { Galleton } from "galleton";
const sessions = new Galleton({ token: localDaemonApiToken });
const result = await sessions.request("account", configuredUpstreamURL);
```

`connect`, `status`, `list`, `refresh`, `headers`, `capture`, `forget`, and `request` share the language-neutral daemon API. `request` attaches authentication and captures replacement cookies. It returns buffered `ManagedResponse` data and never automatically retries the upstream operation.

This is not a browser client. Do not expose the daemon API token to a frontend. See the root Galleton README and SECURITY.md for adapters, setup, and limitations. Provider validity is not guaranteed by the client.
