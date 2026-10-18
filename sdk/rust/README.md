# galleton (Rust)

Blocking local Galleton client. Use a Cargo path dependency on this directory. `request` attaches current authentication and captures replacement cookies through the daemon. Other methods include `connect`, `status`, `list`, `refresh`, `headers`, `capture`, and `forget`.

`Credentials` accepts structured `cookies` (`ImportCookie`). `providers`, `pause` and `resume` list providers and pause or resume their managed requests and renewals; a pause survives a daemon restart. `Error::Api` may carry the daemon codes `upstream_blocked` or `provider_paused` with `retry_at` set.

The initial GitHub CI run compiled this crate and passed its tests on Linux; see [run 36928642430](https://github.com/Microck/galleton/actions/runs/36928642430). Rust was unavailable in the local preparation environment. Check the current PR's Rust job for later revisions. Dependencies are declared in Cargo.toml; the crate is not published and its dependency lockfile is not committed.

See `examples/demo.rs`, the root README, and SECURITY.md. The client only connects to a literal loopback HTTP origin and does not follow redirects or use environment proxies. It is intended for a trusted local/server process, not WebAssembly/browser access. In async applications invoke the blocking client from a worker thread.
