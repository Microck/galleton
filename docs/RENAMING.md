# Naming and existing-state compatibility

The project, executable, npm package, Python distribution/import, and Rust crate are named `galleton`. TypeScript and Python expose `Galleton` and `GalletonError`; Rust exposes `Galleton` and `Error`. The Go module is `github.com/Microck/galleton`, with its client at `github.com/Microck/galleton/client`.

Executable source is in `cmd/galleton`. Environment variables use `GALLETON_`, including `GALLETON_MASTER_KEY`. The default state directory and optional startup-service names use the new name.

## Earlier local state

The encrypted format is deliberately unchanged: `SK01` and its internal `sessionkit:v1:` authenticated-data namespace remain compatible. Continue using the existing state directory with `--dir /existing/state`; supply the same externally managed key bytes under `GALLETON_MASTER_KEY`. The rename does not move, overwrite, or reimport credentials.

Stop an earlier manually installed startup job before installing the newly named job against the same state directory. Do not run both concurrently. Installed-service migration was not tested; the encrypted-state format has a synthetic compatibility regression test.

## Distribution

The repository is `Microck/galleton`. Package names do not imply registry availability. No npm, PyPI, or crates.io publication is performed by this PR. Install SDKs from their source directories; compiled TypeScript output is included, while generated tarballs and wheels are excluded from version control.
