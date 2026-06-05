# AGENTS.md

## Scope
`internal/devtools` — the disposable privileged dev harness. Repo-wide rules in the
root `AGENTS.md` still apply; this adds local rules. Some commands here run as root.

## Purpose
Exercise the privileged broker before any production root install: a foreground
root-smoke broker and a dev-only LaunchDaemon harness. Never a production install.

## Build tag
Every functional file is guarded by `//go:build devtools`. The package is empty in
production builds. Build/test with the tag: `make dev`, `make test-dev`,
`go test -tags devtools ./internal/devtools/`. The CLI wiring is build-tagged in
`cmd/agent-sudo/devtools.go` — do not wire the harness into any untagged file.

## Entry points
- `root_smoke.go` → `CmdRootSmoke`: `run`, `supervise`, `check`, `restart`, `stop`,
  `status`, `cleanup`, `client-artifact`, plus `launchd-dev-*` control via the socket.
- `launchd_dev.go` → `CmdLaunchdDev`: `install`, `status`, `check`, `restart`, `uninstall`.

## Local rules
- Disposable roots only: `/private/tmp/agent-sudo-root-smoke` and
  `/private/tmp/agent-sudo-launchd-dev`; plist `com.bikram.agent-sudo.dev` at
  `/Library/LaunchDaemons/`. Do not point the harness at real config/state/audit paths.
- The supervisor pins the trusted client hash at start and runs the code it was
  started with. After `make dev`, `root-smoke restart` re-trusts the rebuilt client.
- If you change `internal/devtools` OR `internal/broker`, fully stop and re-supervise
  so the root process runs rebuilt code (see references).
- Privileged paths must keep passing `broker.validatePrivilegedBrokerPaths`
  (root-owned, non-symlink, not group/world-writable).

## Testing
- `make test-dev` for harness changes.
- Privileged smoke: `make dev` then `sudo ./agent-sudo root-smoke run` (or
  `supervise` for the dev loop). Recovery: `sudo ./agent-sudo root-smoke cleanup`.

## References
- Flows, gotchas, macOS privacy note: `../../docs/testing.md`, `../../README.md`.
- Security invariants the harness verifies: `../../docs/security-invariants.md`.
