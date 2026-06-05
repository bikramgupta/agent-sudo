# AGENTS.md

## Scope
Applies repo-wide. `internal/devtools/AGENTS.md` specializes the privileged dev harness.

## Project summary
`agent-sudo` is a local privileged broker (Go) that lets AI coding agents request
constrained admin actions over a Unix domain socket instead of raw `sudo`. The CLI
and broker ship in one binary; the broker owns trust, policy, artifact verification,
no-shell execution, and an append-only audit log. Default deny — anything not
matching an exact low-risk policy is denied or escalated. Stage 1 (rootless) plus a
disposable privileged dev harness are built; production root install, approval UX,
and update/uninstall are not.

## Repository map
| Path | Purpose | Deeper doc |
| --- | --- | --- |
| `cmd/agent-sudo/` | Thin entrypoint; `devtools.go` wires the harness (build-tagged) | — |
| `internal/` | All broker/CLI logic in focused packages | docs/architecture.md |
| `internal/devtools/` | Disposable root-smoke / launchd-dev harness (`-tags devtools`) | internal/devtools/AGENTS.md |
| `docs/` | Design, threat model, acceptance tests | docs/broker-design.md |
| `Makefile` | Build/test/vet/fmt targets | — |
| `agent-sudo`, `.gocache/` | Built binary and module-local GOCACHE — gitignored; do not edit or commit | — |

## Common commands
- `make build` — production binary, no harness — Verified
- `make dev` — dev binary incl. harness (`-tags devtools`) — Verified
- `make test` — rootless test gate (`go test ./...`) — Verified
- `go test ./internal/cli/` — targeted package test — Verified
- `make vet` — vet both tag configurations — Verified
- `make test-dev` — full gate incl. harness tests — Inferred from Makefile (not run)
- `make fmt` — `gofmt -w` (mutates sources) — Inferred from Makefile (not run)
- `sudo ./agent-sudo root-smoke run` — privileged smoke; needs `make dev` first — Inferred from README (privileged, not run)

## Working rules
- Default deny. Unmatched requests return `REVIEW_REQUIRED`; never make them run. Preserve the check order in `internal/broker/broker.go` `process()`.
- argv arrays only, never a shell. Do not add `sh -c` / pipe / redirection execution. Executables must be absolute; no PATH resolution.
- Keep the harness behind `-tags devtools`. Production code must not import `internal/devtools`; `cmd/agent-sudo/devtools.go` is the only (build-tagged) wiring.
- The broker derives client identity from the Unix peer (`internal/peer`), reconciled against the trust store — never trust request-JSON identity alone.
- Artifacts are content-addressed and re-hashed immediately before execution; reject symlink / hardlink / writable-parent / TOCTOU. Do not bypass `artifact.Verify` or `internal/broker/path_security.go`.
- Audit is append-only JSONL with bounded, secret-redacted output. Do not log full env or raw output; keep `schema_version` stable (`internal/audit`).
- Production paths (`/var/run`, `/var/log`), approval UX, and update/uninstall are NOT implemented — do not document or assume them as built.

## Testing expectations
- Logic changes (broker/policy/artifact/audit/cli/trust/peer): `make test`.
- Harness changes (`internal/devtools`): `make test-dev`; privileged paths need `make dev` then `sudo ./agent-sudo root-smoke run`.
- Run `make vet` (covers both build tags) before calling a change done.
- New policy/argv/path/artifact behavior needs negative tests — failing closed is a release gate, not optional hardening. See docs/testcases.md.
- Docs-only changes: no tests required.

## Navigation hints
- Architecture & request lifecycle: docs/architecture.md
- Security invariants (as-built, must-not-break): docs/security-invariants.md
- Testing flows & gotchas: docs/testing.md
- Design & threat model: docs/broker-design.md
- Acceptance test matrix: docs/testcases.md
- Privileged dev harness: internal/devtools/AGENTS.md

## Maintenance rule
When you change code, update the nearest AGENTS.md or linked reference doc if the change alters architecture, commands, conventions, API contracts, auth/security behavior, data models, generated-code workflow, deployment behavior, or testing strategy. When you add a new deployable service, app, package, crate, or major subsystem, create or update the appropriate AGENTS.md in the same change.
