# Testing

Agent-facing testing guide. The README has the full prose; this is the
which-gate-for-which-change summary plus the gotchas that bite.

## Gates
| Command | Covers | When |
| --- | --- | --- |
| `make test` | Rootless gate, `go test ./...` (no build tag) | Any logic change |
| `make vet` | `go vet` for both tag configs | Before calling any change done |
| `make test-dev` | Full gate incl. `-tags devtools` harness tests | Changes under `internal/devtools` |
| `sudo ./agent-sudo root-smoke run` | Disposable privileged smoke (needs `make dev`) | Privileged broker / execution changes |

Tests are deterministic and rootless by default; only the `root-smoke` and
`launchd-dev` flows need `sudo`. The module-local cache is `.gocache/` (set by the
Makefile via `GOCACHE`); leave it gitignored and untracked.

## Which change runs what
- `internal/cli`, `internal/broker`, `internal/policy`, `internal/artifact`,
  `internal/audit`, `internal/trust`, `internal/peer`, `internal/protocol`,
  `internal/config`, `internal/fsutil` → `make test`.
- `internal/devtools` (harness) → `make test-dev`, then the privileged smoke if you
  touched execution or path-ownership behavior.
- Docs only → nothing required.

Test files today live in `internal/broker/path_security_test.go`,
`internal/cli/cli_test.go`, and (build-tagged) `internal/devtools/*_test.go`.

## Negative tests are release gates
Failing-closed behavior is the product. New policy/argv/path/artifact behavior
must ship with a negative test asserting the deny/`REVIEW_REQUIRED` path, not just
the happy path. The target matrix (weak reason, reason/command mismatch, unknown
client, shell string, TOCTOU swap, hash mismatch, symlink, writable parent, env
injection, output secrets, timeout) is in `docs/testcases.md`.

## Privileged harness gotchas
The supervisor pins the trusted client hash at start and runs the code it was
started with. After `make dev`:
- `./agent-sudo root-smoke restart` re-trusts the rebuilt client binary.
- If your change touched `internal/devtools` or `internal/broker`, fully stop and
  re-supervise so the root process runs rebuilt code:
  `./agent-sudo root-smoke stop && sudo ./agent-sudo root-smoke supervise`.
- On macOS a root LaunchDaemon may be unable to hash a client under `~/Documents/...`
  (privacy controls); use the copied binary the harness installs under its dev root.

See `internal/devtools/AGENTS.md` for the harness command surface and dev roots.
