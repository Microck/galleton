# galleton (Rust)

Blocking local galleton client. Use a Cargo path dependency on this directory. `request` attaches current authentication and captures replacement cookies through the daemon. Other methods include `connect`, `status`, `list`, `refresh`, `headers`, `capture`, and `forget`.

This crate is source-complete but has not been compiled in the distribution environment, which lacks Rust and dependency-network access. Run `cargo test` before adoption. No resolved Cargo.lock or successful CI run is claimed. Dependencies are declared in Cargo.toml; the crate is not published.

See `examples/demo.rs`, the root README, and SECURITY.md. The client only connects to a literal loopback HTTP origin and does not follow redirects or use environment proxies. It is intended for a trusted local/server process, not WebAssembly/browser access. In async applications invoke the blocking client from a worker thread.
