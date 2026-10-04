# Verification

## Historical local publication checks

This table is a historical snapshot from preparation of the initial GitHub PR, not the current PR test counts. Later PR validation expanded the Node SDK suite to seven tests and the Python SDK suite to ten; current-head CI is the source for the latest results.

| Check | Result |
|---|---|
| `go test -race -count=1 -cover ./...` | Passed; 35 tests, client coverage 86.0%, core coverage 74.4% |
| `go vet ./...` | Passed |
| TypeScript compilation | Passed |
| Node SDK tests | 5 passed |
| Python SDK tests | 5 passed |
| Real-process integration | 8 checks passed |

Local tools: Go 1.23.2, Node 22.16.0, Python 3.13.5. This is a record of the local run, not a recommendation to deploy old toolchains.

The integration test imports OAuth and cookie credentials once, uses both Python and compiled TypeScript clients, continues beyond the original 12-second refresh/cookie lifetimes, restarts the daemon without reimporting, checks origin restrictions, verifies credential-free CLI metadata, and checks that session files contain no plaintext demo credentials. All accounts are synthetic loopback-only fixtures.

The Go suite also covers concurrent refresh coordination, terminal provider refusals, rate limits, lost responses, crash checkpoints, failed local writes, cookie scope/deletion, configuration changes, vault authentication, profile isolation, shutdown, safe connection-failure recovery, and compatibility with the earlier encrypted format.

## Remote verification

The workflow tests Go on Linux, macOS, and Windows, SDK/integration behavior, and Rust separately. A configured job is not a completed result: inspect the PR's current checks and review comments for the latest commit. The Rust toolchain was unavailable locally.

## Not established

No live-provider compatibility, indefinite authorization, independent security audit, long-term production reliability, physical power-loss durability, or successful OS startup-installer execution is claimed. No package registry publication or release approval is implied by passing tests. Historical generated archives and test logs are not committed; tests are reproducible from source.
