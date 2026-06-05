# Local AI Privilege Broker Design

## Goal

Let local AI agents perform selected privileged actions through an auditable
broker, without granting the agent raw `sudo` or creating a broad local attack
surface.

The UX must work even when a given agent has no plugin system. The portable
contract is a command line interface that the agent can run.

## Non-Goals

- Do not provide general unrestricted `sudo`.
- Do not expose an HTTP API on the LAN.
- Do not depend on Codex-, Claude-, Cursor-, or OpenCode-specific plugin APIs
  for the base experience.
- Do not claim perfect client identity from a plain process name.
- Do not claim to secure a fully compromised user account.
- Do not make human approval the normal path for narrow, already-approved
  operations.

## Threat Model And Guarantees

The product should reduce accidental and unaudited privileged execution by local
AI agents. It is a constrained delegation system, not a complete local endpoint
security product.

It should protect against:

- agents bypassing local policy by invoking raw `sudo`
- unconfigured local tools using the broker by accident
- shell-string expansion and argument-shape confusion
- broad privileged access when a narrow typed policy would be enough
- unreviewed URL-fetched scripts and installer artifacts
- missing audit records for brokered privileged actions

It should assume:

- local project scripts, package postinstall hooks, or downloaded binaries may be
  hostile
- any process running as the same user may try to invoke the CLI
- process names, argv, environment variables, and user-writable config are weak
  identity signals by themselves
- root-owned policy, root-owned logs, Unix peer credentials, executable metadata,
  optional code signatures, scoped policies, and bounded approvals are layered
  controls, not perfect proof of user intent

It does not guarantee:

- preventing abuse after the user's account is fully compromised
- preventing direct `sudo` bypass if agents still have broad sudoers access,
  cached credentials, or password access
- proving that a package manager or installer will not run hooks or fetch
  second-stage code

`agent-sudo self-test` should report residual bypass risk, including broad
passwordless sudo rules where detectable, unsafe socket or policy permissions,
user-writable production logs, and unsafe artifact-store ownership.

## Command Surface

Recommended binary name: `agent-sudo`.

Avoid naming the primary executable `sudoctl` unless there is a strong reason.
It sounds good, but `agent-sudo` is clearer for agents and humans, and it is
less likely to be confused with system tooling.

Core commands:

```sh
agent-sudo install
agent-sudo status
agent-sudo session start
agent-sudo fetch --url <url> --sha256 <hash>
agent-sudo artifact import <path>
agent-sudo artifact inspect <artifact-id>
agent-sudo artifact run --reason <text> [--session <id>] <artifact-id> [-- args...]
agent-sudo self-test
agent-sudo trust add <client-id> --path <absolute-path>
agent-sudo trust list
agent-sudo policy list
agent-sudo policy test -- <command> [args...]
agent-sudo request --reason <text> [--session <id>] -- <command> [args...]
agent-sudo audit tail
agent-sudo audit show <request-id>
```

Agent instruction snippet:

```text
For privileged local actions, do not run sudo directly.
Use: agent-sudo request --reason "<short reason>" -- <absolute command and args>
Prefer project-documented commands and include the reason in one sentence.
```

## UX Model

The product has two distinct UX surfaces.

Human setup UX:

- install `agent-sudo`
- enable the broker
- enroll trusted agents such as Codex or Claude Code
- configure policy
- inspect audit logs

Agent runtime UX:

- a short instruction tells the agent not to call `sudo` directly
- the agent calls `agent-sudo request`
- exact low-risk policy matches run without a human prompt
- the broker returns structured results, approval requirements, or retryable
  rejections
- the agent can revise the reason, command, or scope and retry

This split matters. The one-time install can use a human-facing installer with
normal macOS prompts. The agent-facing path should be deterministic, concise,
and scriptable.

The design principle is: policy is the normal boundary, and human approval is
the exception path. If the product prompts for every useful privileged action,
users and agents will work around it with raw `sudo`.

## Broker Reply Contract

Declines should be structured and useful to the agent. The CLI should print a
human-readable message, but the socket response should carry stable machine
fields:

```json
{
  "request_id": "req_...",
  "decision": "REASON_INVALID",
  "message": "Reason does not explain why the command is needed for this task.",
  "retryable": true,
  "missing": ["task_context", "expected_outcome"],
  "suggested_reason_shape": "Need to <action> because <project/task requires it>; target is <scope>."
}
```

Recommended decisions:

- `APPROVED`
- `DENIED`
- `REVIEW_REQUIRED`
- `REASON_INVALID`
- `POLICY_MISMATCH`
- `CLIENT_NOT_TRUSTED`
- `SESSION_INVALID`
- `ARTIFACT_UNVERIFIED`
- `SCOPE_TOO_BROAD`

Agents should treat retryable responses as a request to revise the command,
reason, or scope and try again through the same CLI.

## Request Flow

1. Agent invokes `agent-sudo request` or `agent-sudo artifact run`.
2. CLI builds a structured request:
   - executable path
   - argv array
   - cwd
   - sanitized environment metadata
   - reason
   - optional session id
   - artifact id and artifact hash when executing a script or fetched file
   - requesting uid/gid
   - parent process metadata when available
3. CLI sends the request to a Unix domain socket.
4. Broker verifies peer credentials and configured trust rules.
5. Broker validates the reason and checks command/reason consistency.
6. Broker evaluates policy and risk classification.
7. Broker asks for human approval only when policy, risk, or lifecycle state
   requires it.
8. Broker executes without a shell.
9. Broker logs the request, decision, and result.
10. CLI returns stdout, stderr, exit code, and any retryable broker guidance to
    the agent.

## Reason Validation

The broker should require a reason, and it should reject reasons that are too
generic or inconsistent with the command. This is not a replacement for policy,
but it improves audit quality and gives the agent a clean back-and-forth path.

Minimum deterministic checks:

- non-empty and within configured length bounds
- not generic filler such as `needed`, `fix issue`, or `sudo required`
- names the intended action and expected outcome
- identifies the target scope when the command mutates files, services, users,
  network state, packages, disks, or permissions
- is consistent with the matched policy category

Examples:

```text
bad:  need sudo
good: Validate the generated Lima sudoers file before enabling bridged networking.

bad:  install dependency
good: Install jq because the project scripts call jq during local verification.
```

Optional semantic checks can use a local model or heuristic classifier, but
semantic checks should not be the sole security boundary. The durable security
decision should still come from client trust, policy match, risk category, and
approval rules.

## Session Model

Default to request-stateless behavior. Each request should carry enough
information to be evaluated independently.

Session awareness is still useful for UX and auditing:

- group related requests under one `session_id`
- show an audit trail for a single agent run
- preserve a short human-approved lease for one exact policy, client, cwd, and
  target scope
- let the broker tell an agent that a session is unknown or expired

What sessions must not do:

- grant broad ambient privilege after one approval
- make a later command safe because an earlier command was approved
- store full prompt history or sensitive context by default
- allow one client to reuse another client's approval

If approval caching is added, leases should be explicit, short-lived, scoped to
the exact policy and target, and visible in the audit log.

## Approval Model

Human approval is not the primary security boundary for routine work. It exists
for cases where policy cannot safely decide alone, where a human is changing the
standing authority model, or where the effect is high-risk enough that a
machine-readable policy match should still pause.

Approval should be required for:

- first-time client enrollment and re-enrollment after executable metadata
  changes
- policy creation, policy edits, and policy migration
- unmatched `REVIEW_REQUIRED` requests
- destructive or high-risk effects
- raw shell, interpreter, or broad command policies
- unsigned, unverified, or runtime-network-capable artifacts
- broad approval leases
- broker install, update, downgrade, uninstall, and recovery operations

Approval should not be required for:

- exact low-risk policy matches
- validation-only commands with exact executable, argv shape, cwd, target scope,
  client id, timeout, and environment allowlist
- approved read-only or inspect-only actions
- repeated commands covered by a short exact lease with no changed target or argv
  shape

Approval prompts must show the exact executable, argv, cwd, resolved targets,
policy id, effect category, client identity, reason, artifact hash when present,
and whether the approval is one-time or leased. Destructive effects should
require stronger confirmation than a single keystroke, such as typing the target
or policy id.

Approval leases must be short, visible, revocable, and bound to exact client id,
cwd, policy id, executable, argv shape, target scope, artifact hash when
present, and duration. A lease must never mean "this agent has sudo for 30
minutes." Repeated approval prompts should be rate-limited and offer a clear
"deny this session" path.

## Client Allowlisting

The desired policy is "only accept requests from configured agents such as
Codex or Claude Code." That should be treated as a core requirement, but it
must be implemented honestly.

A simple process-name check is weak. Any local process can spoof a name or call
the CLI directly. Stronger layers:

- Unix socket permissions restrict which users/groups can connect.
- Peer credentials prove the connecting uid and pid to the broker.
- The broker can inspect process path and ancestry where the OS supports it.
- macOS builds can optionally verify code signatures for known app binaries.
- Enrollment creates a per-client config and token stored with user-only file
  permissions.
- High-risk, raw, or unmatched commands still require human approval or denial.

This does not make it impossible for malicious code running as the same user to
attempt a request. The security target is to prevent accidental raw sudo,
network exposure, unconfigured tools, and unlogged privileged actions, while
making abuse visible and policy-constrained.

## Local-Only Boundary

Do not start with TCP, even bound to `127.0.0.1`.

Use:

```text
~/.agent-sudo/run/broker.sock        development mock
/var/run/agent-sudo/broker.sock      root launchd service
```

Socket permissions should be restrictive. The production broker should be
root-owned, and policy files should be writable only by root/admin.

## Policy Model

Policies should be typed and template-based first, raw-command-based second.

Example policy shape:

```yaml
version: 1
rules:
  - id: homebrew.install.named
    clients: ["codex", "claude-code"]
    executable: /opt/homebrew/bin/brew
    argv:
      - install
      - { enum: ["jq", "gh"] }
    effect: install_or_update
    target_scope:
      packages: ["jq", "gh"]
    approval: not_required
    cwd:
      allow: ["$HOME/Documents/Build"]
    env:
      allow: ["HOME", "TMPDIR"]
      clear_prefixes: ["DYLD_", "LD_"]
    locks: ["homebrew"]
    timeout_seconds: 900

  - id: sudoers.validate
    clients: ["codex"]
    executable: /usr/sbin/visudo
    argv:
      - -c
      - -f
      - { prefix: "/etc/sudoers.d/" }
    effect: validate_only
    approval: not_required
    env:
      allow: []
    timeout_seconds: 30
```

Rule evaluation should reject by default. If no rule matches, return a
`REVIEW_REQUIRED` decision rather than silently running the command.

Policies should bind decisions to:

- absolute executable path
- exact argv array shape
- client ids
- effect category
- target scope
- cwd constraints where relevant
- environment allowlist and cleared prefixes
- timeout and output limits
- approval mode
- lock resources
- artifact hash or artifact trust rule when applicable

Reject relative executables, implicit path resolution, broad wildcards, `sh -c`,
`bash -c`, interpreter escape hatches, globbing, pipes, redirection, command
substitution, and shell metacharacter patterns unless an explicit high-risk
policy exists for that exact use case. Canonicalize and validate paths before
policy evaluation.

## Destructiveness And Risk

The broker should try to prevent destructive actions, but it should not claim a
universal "non-destructive command" guarantee. Many useful privileged commands
intentionally mutate the machine: package installs, service restarts, permission
fixes, network changes, and file writes.

Use explicit effect categories:

```yaml
effects:
  - read_only
  - validate_only
  - install_or_update
  - service_control
  - file_write
  - permission_change
  - network_change
  - disk_or_partition_change
  - destructive
```

Rules should declare allowed effects and approval requirements. The broker
should infer risk from both the executable and arguments, then compare that to
the rule. Examples:

- `visudo -c -f <file>` can be `validate_only`.
- `brew install <package>` is `install_or_update`.
- `launchctl bootout`, `rm`, `chmod -R`, `chown -R`, `diskutil eraseDisk`,
  `mkfs`, `dd`, and shell interpreters should be high-risk or destructive by
  default.

For high-risk effects, require some combination of:

- explicit policy match
- exact target scope
- human approval
- dry-run or validation command when available
- backup or rollback note when applicable
- bounded timeout and output capture

Do not run shell strings as privileged commands. Reject `sh -c`, redirection,
command substitution, and shell metacharacter patterns unless a highly specific
policy exists for that exact use case.

## Scripts And URL-Fetched Installers

Running a script with privilege is a valid workflow. Fetching a URL and then
running the result with privilege is also a valid workflow. Both should be
treated as high-risk artifact workflows, not ordinary command execution.

Do not normalize this pattern:

```sh
curl https://example.invalid/install.sh | sudo sh
```

Use a staged flow:

```sh
agent-sudo fetch --url https://example.invalid/install.sh --sha256 <expected>
agent-sudo artifact inspect <artifact-id>
agent-sudo artifact run --reason "Install tool X from verified installer for project Y" <artifact-id>
```

Fetch rules:

- fetch without privilege
- require HTTPS unless a policy explicitly allows another source
- allowlist domains for automated fetches
- reject redirects unless policy allows the final host
- require a pinned checksum, signature, or signed release metadata
- enforce size and content-type limits
- store artifacts by content hash
- store artifacts in a private content-addressed directory that is not
  group-writable or world-writable
- log requested URL, final URL, hash, size, content type, and fetch time

Script execution rules:

- execute only a stored artifact id or a policy-allowed local path
- record the exact content hash in the audit log
- verify the hash immediately before execution
- reject world-writable or group-writable scripts and writable parent
  directories unless policy explicitly allows them
- reject symlink path ambiguity unless the resolved path is policy-allowed
- reject hardlink ambiguity unless execution is from the stored content object
- pass arguments as an argv array, never as a shell string
- clear environment variables that can change interpreter behavior
- require approval unless the exact artifact hash and policy are trusted

Installers often download more code at runtime. Policy should model that as a
separate `network_at_runtime` or `installer_with_hooks` risk, because the
reviewed artifact may not be the full code that eventually runs.

Package managers are also script execution surfaces. `brew`, `npm`, `pip`,
`cargo`, and OS package managers can run hooks, postinstall scripts, build
scripts, or compiler toolchains. Treat package installation as
`install_or_update` plus possible `installer_with_hooks`, not as a simple file
copy.

## Corner Cases

Important cases to design for early:

- TOCTOU: a script can change after inspection. Copy scripts into a private
  content-addressed artifact store and verify the hash at execution time.
- Symlinks and hardlinks: resolve paths, reject ambiguous links by default, and
  log both requested and resolved paths.
- Writable parents: a trusted script in a writable directory can be swapped by
  another process. Check parent directory ownership and mode.
- Environment injection: clear `PATH`, `SHELL`, `IFS`, `DYLD_*`, `LD_*`,
  language-specific env vars, and package-manager config unless policy allows
  them.
- Working directory influence: set an explicit cwd and include it in policy
  matching when relative config files could change behavior.
- Shell bypass: reject `sh -c`, pipes, redirection, command substitution, and
  shell metacharacters unless an exact policy exists.
- Runtime network access: a verified installer can fetch unverified code later.
  Model that explicitly and require approval.
- Partial failure: privileged changes can half-complete. Audit the exit code,
  timeout, and rollback note when available.
- Secrets in logs: cap output, hash large output, and avoid logging full
  environment variables or command output that may contain credentials.
- Concurrent requests: serialize conflicting operations such as package manager
  runs, launchd mutations, network changes, disk changes, and policy edits.
- Policy edits: policy files must be root/admin-owned and validated before
  activation; policy changes should have their own audit events.
- Self-update and uninstall: broker updates, broker removal, and policy
  migration need separate high-risk policies and clear recovery behavior.
- Same-user attacker: a malicious local process running as the same user may be
  able to invoke the CLI. Client allowlisting, peer checks, tokens, and approval
  reduce risk, but they are not a perfect boundary against same-user compromise.
- Direct sudo bypass: if the agent can still get a password or a broad sudoers
  rule, it can bypass the broker. The integration should instruct agents to use
  the broker, and local sudoers policy should avoid broad agent privileges.

## Concurrency And Partial Failure

Privileged operations are not safely parallel by default. The broker should
serialize or reject conflicting mutations with global and resource-specific
locks.

Lock resources should cover at least:

- package managers
- service managers and launchd state
- network interfaces and routes
- disks, partitions, and mounts
- policy files and policy activation
- broker update, downgrade, recovery, and uninstall
- artifact ids and artifact-store garbage collection

The CLI should expose queue and lock visibility through `agent-sudo status`.
Retryable requests should use idempotency keys where practical so an agent retry
does not duplicate a privileged mutation.

Partial failure must be explicit. A command that times out, exits non-zero after
mutation, loses the client connection, or is interrupted by sleep/reboot should
not be reduced to a plain exit code. Audit records should include before/after
state where practical, timeout state, interrupted/unknown result markers, and a
rollback note for high-risk policies.

## Corner-Case Test Strategy

Corner-case protections should have failing tests before the root broker is
enabled. Treat negative tests as release gates, not as optional hardening.

Test layers:

- Unit tests: parser, argv validation, reason validation, policy matching, risk
  classification, audit event shaping.
- Artifact tests: fetch, import, hash verification, path resolution, symlink
  rejection, writable-parent detection, artifact execution requests.
- User-mode integration tests: CLI to mock broker over a Unix socket, default
  deny, retryable broker responses, session grouping, bounded output.
- Privileged integration tests: launchd/root broker, root-owned policy, socket
  permissions, and execution behavior inside a disposable VM or isolated test
  machine.
- Agent contract tests: simulate Codex/Claude-style retry behavior when the
  broker returns `REASON_INVALID`, `REVIEW_REQUIRED`, or `ARTIFACT_UNVERIFIED`.

Recommended matrix:

| Case | Expected Result | Test Shape |
| --- | --- | --- |
| Weak reason | `REASON_INVALID`, retryable guidance | Request `/bin/echo` with `--reason "sudo"` |
| Reason/command mismatch | `REASON_INVALID` or `POLICY_MISMATCH` | Reason says validate while command installs |
| Unknown client | `CLIENT_NOT_TRUSTED` | Connect with no enrolled client token |
| No matching policy | `REVIEW_REQUIRED` | Request allowed binary with disallowed args |
| Shell string | denied | Try `sh -c`, pipes, redirection, and command substitution |
| TOCTOU script swap | denied | Inspect script, mutate original, execute artifact and verify stored hash is used |
| Hash mismatch | `ARTIFACT_UNVERIFIED` | Fetch/import with wrong checksum |
| Symlink path | denied unless explicitly allowed | Import or execute a symlink to a sensitive path |
| Writable parent | denied | Script under a group/world-writable directory |
| Environment injection | sanitized or denied | Set `DYLD_*`, `LD_*`, `PATH`, package-manager config vars |
| Runtime network installer | review required | Artifact contains a second-stage download |
| Package hook installer | review required | Package install policy marks hook-capable tools high risk |
| Output secrets | bounded log | Command prints fake token; audit contains hash/tail only |
| Timeout | terminated and audited | Command sleeps past policy timeout |
| Concurrent mutation | serialized or denied | Two package/service/policy changes at once |
| Policy edit | separate audited event | Attempt policy update with invalid schema or non-root ownership |
| Broker self-update | high-risk approval | Update/uninstall command requires explicit policy |
| Direct sudo bypass | documented residual risk | Confirm agent instruction and sudoers do not grant broad bypass |

Testing recommendations:

- Keep Stage 1 tests rootless and deterministic.
- Use temporary directories with intentionally bad ownership/modes to exercise
  path checks.
- Use a local test HTTP server for fetch, redirect, size-limit, and checksum
  cases.
- Use golden JSON fixtures for broker responses and audit log entries.
- Fuzz argv parsing and policy matching to catch shell-like edge cases.
- Run destructive-effect tests only in disposable VMs or containers.
- Add a `agent-sudo self-test` command that verifies local socket permissions,
  policy file ownership, audit path writability, and artifact-store safety.

## Root Broker Release Gates

The first public root broker should not ship until these gates pass in a
disposable VM or isolated test machine:

- unknown clients, unknown commands, unknown args, generic reasons, unsafe paths,
  unsafe artifacts, unsafe environment, and untrusted policy files fail closed
- request execution uses argv arrays only and never shells out
- client identity does not rely only on process name, CLI arguments, or
  user-editable files
- production policy and audit locations are root-owned and not writable by the
  requesting agent user
- artifact storage is private, content-addressed, hash-verified at execution
  time, and protected against symlink, hardlink, writable-parent, and TOCTOU
  attacks
- logs are bounded, redacted, rotated, crash-safe, and resistant to tampering by
  the agent user
- installer, update, downgrade, migration, and uninstall paths are signed,
  atomic, recoverable, and tested on clean and dirty machines
- high-risk commands require exact policy plus human approval with executable,
  argv, cwd, policy id, effect category, target scope, and rollback note where
  applicable
- package manager, service, network, disk, policy, update, and uninstall
  conflicts are serialized or rejected
- platform-specific behavior is tested across the supported macOS versions, CPU
  architectures, shell environments, and package-manager layouts

## Audit Log

Use append-only JSONL initially:

```json
{
  "schema_version": 1,
  "ts": "2026-06-04T10:15:30-07:00",
  "sequence": 1234,
  "request_id": "req_...",
  "client_id": "codex",
  "uid": 501,
  "peer_pid": 4242,
  "client_executable": "/opt/homebrew/bin/codex",
  "cwd": "/Users/bikram/Documents/Build/example",
  "session_id": "sess_...",
  "reason": "validate sudoers syntax",
  "artifact_id": null,
  "artifact_sha256": null,
  "executable": "/usr/sbin/visudo",
  "argv": ["-c", "-f", "/etc/sudoers.d/lima"],
  "decision": "approved",
  "policy_id": "sudoers.validate",
  "effect": "validate_only",
  "approval": "not_required",
  "approval_expires_at": null,
  "exit_code": 0,
  "timeout": false,
  "duration_ms": 124,
  "stdout_sha256": "...",
  "stderr_tail": "..."
}
```

Do not log full environment variables. Output logging should be bounded and
should avoid storing secrets by default. Store hashes plus short tails unless a
policy explicitly allows full capture.

Production logs should be root-owned, rotated, and quota-bound. The broker
should redact common secret patterns, keep records parseable after crashes, and
fail safely when disk is nearly full. Hash chaining or signed audit segments can
be added later for tamper evidence, but the first root broker still needs stable
schema fields, rotation, redaction, and crash-safety tests.

Suggested locations:

```text
~/.local/state/agent-sudo/audit.jsonl      development/user mode
/var/log/agent-sudo/audit.jsonl            production/root broker
```

## Installation Path

The nice UX is one command, but the safe implementation should be staged.

Stage 1:

- local CLI
- mock broker running as the user
- no privileged execution
- policy matching and audit logs

Stage 2:

- root launchd broker
- Unix socket under `/var/run/agent-sudo`
- install/uninstall commands
- root-owned policy and log directories
- recovery command for broken policy, socket, and service state
- update and uninstall treated as high-risk policy-controlled operations

Stage 3:

- signed macOS release
- checksum verification in install script
- Homebrew tap
- optional per-agent config writers

Example final install UX:

```sh
curl -fsSL https://example.invalid/agent-sudo/install.sh | sh
agent-sudo install --enable-broker
agent-sudo trust add codex --path "$(command -v codex)"
agent-sudo integrate codex
```

Install, update, downgrade, migration, and uninstall are root-code paths. Broad
distribution requires signed and notarized macOS releases, installer signature
or checksum verification, atomic update with rollback, explicit policy schema
migration, downgrade refusal unless in recovery mode, safe uninstall cleanup,
and a canary rollout process before pushing updates widely.

## Platform, Support, And Privacy

Start with a supported platform matrix rather than claiming generic Unix
support. The first privileged release should test macOS Apple Silicon and Intel,
standard Homebrew layouts at `/opt/homebrew` and `/usr/local`, launchd restart
after reboot and sleep, fast user switching, managed Macs that block unsigned
helpers, user home paths with spaces, and broken or missing keychain state after
reboot.

If Linux is added later, design and test it separately for systemd, socket
credentials, PolicyKit interactions, SELinux, AppArmor, and distro package
managers.

Supportability should be built into the CLI:

- `agent-sudo doctor` or `agent-sudo self-test` should emit stable
  machine-readable diagnostics
- error codes should be stable across versions
- support bundles should redact secrets by default
- safe manual recovery steps should be documented for broken policy, broken
  socket, launchd crash loops, package-manager locks, and failed updates

Local operation should not require telemetry. Audit logs can expose project
paths, usernames, hostnames, package names, and workflow intent, so retention,
support export, and any future telemetry should be explicit and configurable.

## Agent Integrations

Keep integrations as generated instructions first:

```sh
agent-sudo integrate codex
agent-sudo integrate claude-code
agent-sudo integrate cursor
agent-sudo integrate opencode
```

Each command should print or install a short instruction block telling the agent
to use `agent-sudo request` and avoid direct `sudo`.

Tool-specific plugins can come later. They should call the same local CLI or
socket protocol, not create separate privilege paths.

## Implementation Decision

Use Go for the CLI and broker implementation.

- one portable binary for CLI and broker subcommands
- good standard library support for Unix sockets, JSON, process execution, and
  timeouts
- easy release packaging compared with Python/Node for a root service
- enough macOS support for launchd integration, with targeted native calls later

Bash should be limited to installer bootstrap tasks: download the release,
verify checksums/signatures, install the binary, and hand off to
`agent-sudo install`. Bash must not be the broker, policy engine, or privileged
execution path.

Do not use Node or Python for the privileged broker. They are fine for tests,
prototypes, or developer tooling, but a root service should minimize runtime
and supply-chain surface.

## First Build Slice

Build the first slice without root:

1. `agent-sudo request --reason ... -- /bin/echo hello`
2. user-mode broker over `~/.agent-sudo/run/broker.sock`
3. policy file under `~/.config/agent-sudo/policy.yaml`
4. JSONL audit file under `~/.local/state/agent-sudo/audit.jsonl`
5. reason validation with `REASON_INVALID` retry guidance
6. artifact fetch/inspect/run for pinned scripts without privilege
7. corner-case negative tests for policy, artifact, and shell-bypass behavior
8. optional session id for audit grouping only
9. no shell execution, argv only
10. default deny with `REVIEW_REQUIRED`

Once that is testable, add launchd/root installation.

## Implementation Status (As Built)

This document is the design and threat model. The Stage 1 rootless slice plus
disposable privileged development gates are implemented; production install,
approval UX, and update/uninstall are not. See the README for the current build
and testing flow.

The code is a Go module (`agent-sudo`) laid out as `cmd/agent-sudo` plus focused
`internal/` packages:

- `protocol` — request/response wire types and the decision/effect vocabulary
- `config`, `fsutil` — path resolution, private-directory checks, hashing
- `policy` — typed matching, effect inference, environment and reason validation
- `trust`, `peer` — client enrollment and broker-derived Unix peer identity
- `artifact` — content-addressed fetch/import/verify
- `audit` — append-only JSONL schema, logger, bounded redacted capture
- `broker` — server, request processing, no-shell execution, privileged path checks
- `selftest`, `cli` — diagnostics and command dispatch
- `devtools` — the disposable root-smoke / launchd-dev harness

The development harness is isolated behind the `devtools` build tag, so the
production binary (`go build ./cmd/agent-sudo`) excludes it entirely, keeping the
shipped root-capable surface minimal as this document recommends.
