# agent-sudo

> **Brokered root for AI agent fleets** — one broker owns root, so your agents don't have to: least privilege, full attribution, complete audit.

`agent-sudo` is a local privileged broker that lets AI coding agents (Codex,
Claude Code, Cursor, OpenCode, and terminal agents) request constrained admin
actions through an auditable boundary instead of being given blanket `sudo`.

Agents call one boring, explicit command:

```sh
agent-sudo request --reason "install package needed by project" -- /opt/homebrew/bin/brew install jq
```

The broker verifies the caller, validates the reason, matches a typed policy,
runs the command without a shell, and records request/decision/result to an
append-only audit log. Anything not covered by an exact low-risk policy is
denied or escalated to human review — default deny, not default allow.

The full design and threat model live in [`docs/broker-design.md`](docs/broker-design.md);
the corner-case matrix is in [`docs/testcases.md`](docs/testcases.md).

## Status

Stage 1 (rootless) is implemented and working end-to-end, plus disposable
privileged development gates:

- Go CLI + user-mode broker in one binary, talking over a Unix domain socket
- argv-array-only execution (no shell), absolute executables only
- broker-derived Unix peer identity (uid/pid/exe/hash) on macOS, reconciled
  against client-supplied metadata and a root-owned-style trust store
- typed policy matching with default deny / review-required
- reason validation with retryable, structured rejections
- content-addressed artifact fetch/import/verify with hash check at run time
- append-only JSONL audit log with bounded, secret-redacted output capture
- disposable root-smoke and launchd-dev harnesses for privileged testing

Not yet implemented: production install paths under `/var/run` and `/var/log`,
the human approval UX, update/uninstall, and production policies for real
administrative workflows. See [Production boundary](#production-boundary).

## Architecture

Two parts, one binary:

1. The `agent-sudo` CLI, run by the agent as the normal user.
2. The broker (`agent-sudo broker serve`), which owns policy, trust, audit, and
   execution. In production it will run as a root launchd service exposed only
   over a Unix socket; today it runs rootless for development.

A Unix socket (not localhost TCP) is used so the broker can inspect peer
credentials and rely on filesystem permissions. The CLI sends a structured
request; the broker replies with a stable machine-readable decision plus, on
approval, the command's stdout/stderr/exit code.

### Code layout

```
cmd/agent-sudo/        # thin entrypoint; tagged file wires in the dev harness
internal/
  protocol/   # request/response wire types, decision + effect constants
  config/     # Paths and AGENT_SUDO_* resolution
  fsutil/     # path canonicalization, private-dir checks, hashing
  policy/     # typed policy matching, effect inference, env + reason validation
  trust/      # client enrollment + executable-hash matching
  artifact/   # content-addressed fetch/import/verify store
  audit/      # JSONL audit schema, logger, bounded redacted capture
  peer/       # Unix socket peer identity (cgo on darwin)
  broker/     # server, request processing, execution, privileged path checks
  selftest/   # self-test diagnostics
  cli/        # command dispatch + user-facing subcommands
  devtools/   # root-smoke / launchd-dev harness  (build tag: devtools)
```

The development harness is compiled in **only** with `-tags devtools`, so the
production binary excludes it entirely — smaller and with less attack surface,
as the design requires for a root service.

## Build

```sh
make build      # production binary (no harness):  go build -o agent-sudo ./cmd/agent-sudo
make dev        # development binary (adds root-smoke / launchd-dev harness)
make test       # rootless test gate
make test-dev   # full test gate, including harness tests
```

The production binary exposes only the user-facing commands; `root-smoke` and
`launchd-dev` exist solely in the dev binary. **Use `make dev` for any of the
testing flows below.**

## Rootless quickstart

```sh
make build
./agent-sudo install                                   # create private rootless paths + default policy
./agent-sudo trust add local-dev --path "$PWD/agent-sudo"
./agent-sudo broker serve                               # in one terminal
```

From another terminal, run an exact low-risk policy match:

```sh
AGENT_SUDO_CLIENT_ID=local-dev ./agent-sudo request \
  --reason "Run echo command for broker project target test." \
  -- /bin/echo hello
```

Inspect state and audit:

```sh
./agent-sudo status
./agent-sudo self-test
./agent-sudo policy test -- /usr/sbin/visudo -c -f /etc/sudoers.d/lima
./agent-sudo audit tail
./agent-sudo audit show <request-id>
```

Default rootless locations (override with `AGENT_SUDO_*`):

| Purpose  | Path |
| --- | --- |
| socket   | `~/.agent-sudo/run/broker.sock` |
| policy   | `~/.config/agent-sudo/policy.yaml` (JSON syntax) |
| trust    | `~/.config/agent-sudo/trust.json` |
| audit    | `~/.local/state/agent-sudo/audit.jsonl` |
| artifacts| `~/.local/state/agent-sudo/artifacts` |

## Agent runtime instruction

Paste this into the agent's project guide:

```text
For privileged local actions, do not run sudo directly. Use:
agent-sudo request --reason "<short reason>" -- <absolute command and args>
Prefer project-documented commands and include the reason in one sentence.
Treat retryable rejections as a request to revise the command, reason, or scope.
```

## Scripts and URL-fetched installers

Running a fetched installer with privilege is a high-risk artifact workflow, so
it is split into verify-first, execute-second:

```sh
./agent-sudo fetch --url https://example.invalid/install.sh --sha256 <expected>
./agent-sudo artifact inspect <artifact-id>
./agent-sudo artifact run --reason "Install tool X from verified installer for project Y" <artifact-id>
```

Fetch requires HTTPS and a pinned checksum; artifacts are stored by content
hash, re-verified immediately before execution, and rejected on symlink,
hardlink, writable-parent, or hash-tamper conditions.

## Testing

### Rootless gate

```sh
make test
```

### Disposable privileged smoke test

The first privileged check is a disposable foreground smoke test, not a launchd
install. It uses only `/private/tmp/agent-sudo-root-smoke`, starts a temporary
root broker, verifies ownership/modes, then checks one positive policy match
(`/usr/bin/id -u` returns `0`) and denials for shell execution, relative
executables, env injection, and artifact hash tamper.

```sh
make dev
sudo ./agent-sudo root-smoke run
```

Recovery if interrupted:

```sh
sudo ./agent-sudo root-smoke cleanup
```

### Supervised dev loop (recommended)

Start the disposable root broker once and leave it running:

```sh
make dev
sudo ./agent-sudo root-smoke supervise
```

From another normal-user terminal:

```sh
./agent-sudo root-smoke check
./agent-sudo root-smoke status
./agent-sudo root-smoke restart            # refresh trusted client hash after a rebuild
./agent-sudo root-smoke launchd-dev-cycle  # install -> check -> audit -> uninstall via the control socket
./agent-sudo root-smoke stop
```

> Rebuilt the binary? The supervisor pins the trusted client hash and runs the
> code it was started with. After `make dev`, run `./agent-sudo root-smoke restart`
> to re-trust the new client binary. **If your change touched the supervisor or
> its control commands** (anything under `internal/devtools` or `internal/broker`),
> stop and re-supervise so the root process runs the rebuilt code:
> ```sh
> ./agent-sudo root-smoke stop
> sudo ./agent-sudo root-smoke supervise
> ```

### launchd-dev harness

`launchd-dev` is the dev-only LaunchDaemon harness:

- plist: `/Library/LaunchDaemons/com.bikram.agent-sudo.dev.plist`
- dev root: `/private/tmp/agent-sudo-launchd-dev`
- copied client binary: `/private/tmp/agent-sudo-launchd-dev/bin/agent-sudo`

```sh
make dev
sudo ./agent-sudo launchd-dev install
./agent-sudo launchd-dev status
```

Manual broker requests should use the copied dev client binary, not the
workspace `./agent-sudo`:

```sh
AGENT_SUDO_SOCKET=/private/tmp/agent-sudo-launchd-dev/run/broker.sock \
AGENT_SUDO_CLIENT_ID=launchd-dev \
/private/tmp/agent-sudo-launchd-dev/bin/agent-sudo request \
  --reason "Read effective uid for broker project target manual launchd verification." \
  -- /usr/bin/id -u
```

Expected output includes `0`. The dev policy is intentionally tiny — only
client `launchd-dev` running `/usr/bin/id -u` is allowed. So `id -u` (relative)
yields `POLICY_MISMATCH` and `/bin/sh -c id` yields `SCOPE_TOO_BROAD`.

> On macOS the root LaunchDaemon may be unable to read/hash a binary under
> `~/Documents/...` due to privacy controls. If `./agent-sudo` as the client
> reports `CLIENT_NOT_TRUSTED` with `operation not permitted`, use the copied
> binary at `/private/tmp/agent-sudo-launchd-dev/bin/agent-sudo`.

Clean up:

```sh
sudo ./agent-sudo launchd-dev uninstall
./agent-sudo launchd-dev status
```

## Security boundary

The development gates verify that, before any production root broker:

- unknown clients, unknown commands/args, generic reasons, unsafe paths, unsafe
  artifacts, and env injection all fail closed
- execution uses argv arrays only and never shells out
- client identity is derived by the broker from the Unix peer, not trusted from
  request JSON alone
- artifacts are content-addressed and hash-verified at execution time, with
  symlink/hardlink/writable-parent/TOCTOU protection
- audit output is bounded and secret-redacted, recording the full-output hash,
  length, and truncation state

This is a constrained delegation system, not a complete endpoint-security
product. It does not defend a fully compromised user account, and it cannot stop
a direct `sudo` bypass if the agent already holds broad sudoers access or cached
credentials. `agent-sudo self-test` reports detectable residual bypass risk.

## Production boundary

The disposable gates above must pass before production install support. As of
this slice there is still no production path under `/var/run` or `/var/log`, no
approval UX, no update/uninstall mechanism, and no production policy for real
administrative workflows. Do not treat the dev harnesses as a production install.
