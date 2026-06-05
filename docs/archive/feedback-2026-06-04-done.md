# Tester Feedback: agent-sudo

Date: 2026-06-04

Status: DONE - incorporated into `docs/broker-design.md` on 2026-06-04.

## Scope

This feedback is based on the current project state: `README.md` and
`docs/broker-design.md`. The product is still design-only. No implementation
exists yet, so every security property in the design should be treated as
unproven until tested.

Product under test: a local privileged broker and CLI that lets local AI agents
request constrained admin actions through `agent-sudo` instead of using raw
`sudo`.

Scale assumption: millions of daily users means millions of local installs,
many OS versions, many agent tools, many package managers, heavy command volume,
enterprise managed machines, multi-user systems, offline machines, hostile
local code, and update rollouts that can break developer machines at once.

## Overall Assessment

The direction is sound: a local Unix-socket broker with structured argv,
root-owned policy, explicit client enrollment, staged artifact handling, default
deny, and timestamped audit logs is the right product shape.

The largest product risk is that this becomes a durable local privilege
escalation mechanism before the boundaries are proven. The first public root
broker release should be blocked until negative tests pass for policy matching,
client identity, shell bypass, artifact TOCTOU, environment sanitization,
socket permissions, audit integrity, updates, and rollback.

## Release Gate Summary

Do not ship a root broker until these gates pass:

- Default-deny behavior is proven for unknown clients, unknown commands,
  unknown args, generic reasons, shell strings, unsafe paths, unsafe artifacts,
  unsafe environment, and untrusted policy files.
- The broker executes argv arrays only and never shells out for request
  execution.
- Client identity is implemented honestly and does not rely only on process
  name, CLI arguments, or user-editable files.
- Root-owned policy and audit locations cannot be modified by the invoking
  agent user.
- Artifact storage is content-addressed, private, hash-verified at execution
  time, and protected against symlink, hardlink, writable-parent, and TOCTOU
  attacks.
- Logs are bounded, redacted, rotated, crash-safe, and resistant to tampering by
  the agent user.
- Installer, update, downgrade, migration, and uninstall paths are signed,
  atomic, recoverable, and tested on clean and dirty machines.
- High-risk commands require human approval with exact executable, argv, cwd,
  policy id, effect category, target scope, and rollback note where applicable.
- Concurrency controls serialize conflicting package manager, service, network,
  disk, policy, update, and uninstall operations.
- Platform-specific behavior is tested on every supported OS version, CPU
  architecture, shell environment, and package-manager layout.

## Severity-Ordered Feedback

### P0: Same-User Abuse Can Defeat Naive Client Allowlisting

Any local process running as the same user may be able to invoke the CLI, read
user-owned config, spoof process names, set environment variables, or launch
through a trusted parent. At large scale, some machines will already have
malicious packages, compromised postinstall scripts, browser downloads, or
project scripts running as the user.

Required controls:

- Do not trust process name alone.
- Use Unix peer credentials, pid/uid checks, executable path checks, parent
  ancestry checks where reliable, and optional code-signature validation on
  macOS.
- Store enrollment tokens with strict permissions and treat them as advisory,
  not as a full boundary against same-user compromise.
- Require approval for raw, destructive, or high-risk requests even from
  trusted clients.
- Log enough process metadata to investigate abuse without storing secrets.
- Document the residual risk clearly: this protects against accidental raw sudo
  and untrusted tools, not a fully compromised user account.

### P0: Policy Matching Must Be Exact, Typed, And Fail Closed

The product breaks badly if a policy intended for one safe form matches a
dangerous variant. Examples include `visudo` validation turning into file
write, `brew install jq` turning into arbitrary package or tap execution,
`chmod` targeting `/`, or a command using relative paths, symlinks, shell
metacharacters, or environment-dependent behavior.

Required controls:

- Match absolute executable paths and argv arrays, not shell strings.
- Canonicalize and validate paths before policy evaluation.
- Reject relative executable paths by default.
- Reject implicit globbing, pipes, redirection, command substitution, `sh -c`,
  `bash -c`, interpreter escape hatches, and shell metacharacter patterns unless
  a very specific policy exists.
- Bind policies to effect categories, target scopes, client ids, cwd constraints
  where needed, timeout, output limit, approval requirement, and environment
  allowlist.
- Add fuzz tests for argv parsing and policy matching.

### P0: Artifact Execution Is A Supply-Chain Boundary

The staged fetch/inspect/run flow is necessary, but it is still easy to get
wrong. A script can change after review, be swapped through a symlink, live
under a writable parent, fetch second-stage code, or use package-manager hooks.
At scale, one bad installer policy could compromise many users.

Required controls:

- Store fetched/imported artifacts by content hash in a private store.
- Verify the stored hash immediately before execution.
- Log requested path, resolved path, artifact id, hash, source URL, final URL,
  size, content type, and execution result.
- Reject world-writable or group-writable scripts and parent directories unless
  policy explicitly allows them.
- Reject redirects by default or require final-host allowlisting.
- Require pinned checksum, signature, or signed release metadata.
- Treat package managers and installers as hook-capable and network-capable.
- Require approval for runtime network access or second-stage downloads.

### P0: Audit Logs Can Leak Secrets Or Become Useless Under Load

Audit is a core promise. It fails if logs can be edited by the agent user, if
full stdout/stderr captures tokens, if logs fill disk, or if high-volume users
cannot search incidents. Millions of daily users will produce huge local log
volumes and many support cases around audit interpretation.

Required controls:

- Use append-only JSONL with stable schema and version fields.
- Make production logs root-owned and not writable by the requesting user.
- Rotate logs and enforce disk quotas.
- Bound stdout/stderr capture; store hashes and short tails by default.
- Redact common secret patterns and avoid logging full environment variables.
- Include decision, policy id, effect, approval state, client metadata, cwd,
  executable, argv, artifact hash, exit code, timeout, and duration.
- Add crash-safety tests that kill the broker mid-request and verify logs remain
  parseable and truthful.
- Consider hash chaining or signed audit segments for tamper evidence.

### P0: Human Approval Can Be Social-Engineered Or Fatigued

An AI agent can generate plausible but wrong reasons. At high volume, users may
approve prompts reflexively, especially if every request looks urgent or
technical.

Required controls:

- Approval UI must show exact executable, argv, cwd, resolved targets, policy
  id, effect category, risk, client identity, and reason.
- For destructive effects, require an explicit typed confirmation or a
  second-step approval.
- Do not approve based on reason text alone.
- Make approval leases short, scoped to exact policy, target, client, cwd, and
  command shape.
- Rate-limit repeated prompts and expose "deny all for this session".
- Log approval source, timestamp, scope, and expiration.

### P0: Installer, Update, And Uninstall Are Root-Code Paths

The install/update path is as sensitive as request execution. A broken update
could disable developer machines, weaken policies, replace the broker binary,
or leave stale privileged services running.

Required controls:

- Signed and notarized releases for macOS before broad distribution.
- Installer verifies checksums or signatures before installing.
- Atomic install and update with rollback.
- Versioned policy schema and migration validation.
- Refuse downgrade unless explicitly approved.
- Safe uninstall removes launchd service, socket, helper binary, temporary
  files, and leaves audit logs according to user choice.
- Recovery command for broken policy or socket state.
- Canary release process before pushing to all users.

### P0: Direct `sudo` Bypass Undermines The Product

If agents still have broad sudoers access, cached sudo credentials, or human
password access, they can bypass `agent-sudo`. The product cannot guarantee
auditable privilege in that environment.

Required controls:

- `agent-sudo self-test` should detect broad passwordless sudo where possible
  and warn that bypass is possible.
- Integration snippets must instruct agents not to run `sudo` directly.
- Docs should recommend avoiding broad agent sudoers rules.
- Audit reports should distinguish brokered privileged actions from residual
  local sudo outside the broker.

### P1: Platform Behavior Will Drift

Unix socket credentials, code signing checks, launchd behavior, file modes,
package-manager paths, and shell environments differ by OS version,
architecture, managed-device policy, and user setup.

Required controls:

- Maintain a supported platform matrix.
- Test macOS Intel and Apple Silicon.
- Test standard `/opt/homebrew` and `/usr/local` layouts.
- Test launchd service restart after reboot, sleep, fast user switching, and
  OS update.
- If Linux is supported later, test systemd, PolicyKit interactions, SELinux,
  AppArmor, and common distro package managers separately.

### P1: Concurrency Can Corrupt The Host

Multiple agents, tabs, terminals, or retry loops may issue concurrent requests.
Package managers, service management, network changes, disk operations, policy
edits, and broker updates are not safely parallel by default.

Required controls:

- Global and resource-specific locks.
- Queue visibility in `agent-sudo status`.
- Clear timeout and cancellation behavior.
- Idempotency keys for retryable requests where practical.
- Conflict detection for package managers, services, disk targets, network
  interfaces, policy files, and artifact ids.

### P1: Partial Failure Needs First-Class Handling

Privileged commands can half-complete. A package install may install files but
fail postinstall. A network command may drop connectivity. A policy edit may be
written but not activated. A timeout may kill a process that already mutated
state.

Required controls:

- Audit before and after state when practical.
- Require rollback notes for high-risk policies.
- Prefer validation or dry-run commands before mutation.
- Surface partial failure explicitly, not just exit code.
- Add recovery playbooks for broken broker service, broken policy, and broken
  package-manager lock.

### P1: Sessions Can Become Ambient Authority

Sessions are useful for grouping, but approval caching can become a broad
privilege lease.

Required controls:

- Sessions must not grant privilege by themselves.
- Leases must be short, visible, revocable, and bound to exact client, cwd,
  policy, effect, executable, args, and target scope.
- One client must never reuse another client's lease.
- Session ids should be unguessable.

### P1: Reason Validation Is Useful But Not A Security Boundary

Reason checks improve audit quality and agent retry UX. They do not prove that
the command is safe.

Required controls:

- Keep reason validation deterministic and testable.
- Reject generic or inconsistent reasons.
- Never allow a better reason to override policy mismatch or missing approval.
- Avoid sending sensitive prompt context to remote services for reason checks.

### P1: Observability And Support Need Design Before Scale

Millions of users means many support tickets: stuck sockets, broken launchd,
policy mismatch, permission denied, checksum mismatch, approval prompt issues,
and package manager locks.

Required controls:

- `agent-sudo doctor` or `self-test` should return machine-readable diagnostics.
- Error codes must be stable.
- Logs should include enough metadata to debug without collecting secrets.
- Support bundle export should redact sensitive fields by default.
- Document safe manual recovery steps.

### P2: UX Failures Will Cause Unsafe Workarounds

If the CLI is noisy, slow, ambiguous, or hard to configure, users and agents
will bypass it with raw sudo.

Required controls:

- Keep agent-facing errors concise and retryable where possible.
- Include suggested fixes in `REASON_INVALID`, `POLICY_MISMATCH`, and
  `ARTIFACT_UNVERIFIED`.
- Make common safe workflows easy: validate sudoers, install a named package,
  restart a named service, inspect audit log.
- Make dangerous workflows visibly different.

### P2: Privacy And Enterprise Controls Need Early Boundaries

Audit logs can expose project paths, package names, usernames, hostnames, and
workflow intent. Enterprises may need retention, export, disablement, and policy
management.

Required controls:

- Local-only operation by default.
- No telemetry by default unless explicitly designed and disclosed.
- Configurable retention.
- Redacted support bundles.
- Enterprise policy lock support if this becomes a managed deployment product.

## Open Product Questions

- What OS versions are officially supported at first release?
- Is Linux in scope for v1, or macOS-only?
- Will any central service exist for updates, revocation metadata, policy packs,
  or telemetry?
- What is the exact threat model for same-user compromise?
- Which commands are intended as built-in policies for v1?
- How will users recover if the broker is broken but still installed as root?
- How long should audit logs be retained by default?
- Will high-risk approval be terminal-based, macOS GUI-based, or both?
- How will signed release verification work before Homebrew tap availability?
- What is the minimum viable enterprise story for managed Macs?

## Recommended Build Order

1. Rootless CLI plus mock broker over a Unix socket.
2. Structured request/response schema with golden fixtures.
3. Default-deny policy engine and reason validation.
4. Audit JSONL schema, rotation, redaction, and crash-safety behavior.
5. Artifact fetch/import/inspect/run in user mode with hash checks.
6. Adversarial tests for shell bypass, paths, symlinks, writable parents,
   environment injection, and policy mismatch.
7. Privileged broker inside disposable VM only.
8. Installer/update/uninstall recovery tests.
9. Platform matrix and canary release process.
10. Public root-broker release.
