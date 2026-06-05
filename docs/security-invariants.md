# Security Invariants (as built)

This is the must-not-break list for the implemented code, anchored to files and
the test that proves each one. `broker-design.md` is the full threat model; this
doc is what an agent editing the code has to preserve. Breaking any of these
silently weakens the privilege boundary.

## Default deny
- No matching policy → `REVIEW_REQUIRED` (or `SCOPE_TOO_BROAD` for shell-like
  requests), never silent execution. See `broker.process` in
  `internal/broker/broker.go` and the lifecycle in `docs/architecture.md`.
- Keep the check order in `process`: schema → trust → arg shape → artifact verify
  → reason → policy match → effect/approval/shell/env → execute. Reordering can
  let a request reach `execute` before a control runs.

## No shell, argv only
- Execution passes an argv array to `os/exec`; the broker never builds a shell
  string. Do not add `sh -c`, pipes, redirection, globbing, or command
  substitution paths.
- Shell executables and shell metacharacters in argv are rejected with
  `SCOPE_TOO_BROAD` unless an exact high-risk policy allows them
  (`policy.IsShellExecutable`, `policy.HasShellMetacharacters`, `policy.ShellDenied`).
- Executables must be absolute and null-byte-free; argv is null-byte-checked and
  count-capped (128). No PATH resolution is performed.

## Client identity from the peer, not the request
- Trust is matched against broker-derived Unix peer identity (uid/pid/exe/hash)
  in `internal/peer`, reconciled with client-supplied metadata via `trust.Match`.
- Never approve based on request-JSON identity alone. Mismatch → `CLIENT_NOT_TRUSTED`.

## Artifact verification (TOCTOU-safe)
- Artifacts are content-addressed and re-verified immediately before execution:
  `artifact.Verify` re-lstats the stored object, rejects symlinks, and the broker
  re-checks request hash vs stored metadata and the stored object path
  (`broker.process`, step 4).
- Import rejects symlink paths, hardlinked files (`Nlink > 1`), symlink parents,
  and group/world-writable parent directories (`rejectUnsafeSourcePath`).
- Runtime risk flags (`scanArtifactRisks`) force `REVIEW_REQUIRED`. Do not auto-approve
  artifacts with risk flags.
- Fetch requires HTTPS and a pinned `--sha256`; content is stored by hash. Keep
  those preconditions in `Store.Fetch`.

## Privileged-path ownership (root broker)
- When `euid == 0`, `validatePrivilegedBrokerPaths` (`internal/broker/path_security.go`)
  requires run/config/audit/artifact dirs and policy/trust files to be root-owned,
  non-symlink, and not group/world-writable (`Perm & 0o022 == 0`). Don't relax these
  checks or add user-writable production paths.

## Audit: bounded, redacted, append-only
- Output capture is size-limited with `Capture`; the audit record stores the
  full-output SHA-256, length, truncation state, and a redacted tail — never the
  raw unbounded output (`internal/audit/audit.go`).
- `RedactSecrets` masks `api_key/token/secret/password=...` patterns before any
  capture is logged. Extend the patterns rather than logging raw output.
- Never log full environment variables. Keep `schema_version` (currently 1) stable;
  bump it deliberately if the record shape changes.

## Build-tag isolation
- The dev harness lives behind `-tags devtools`. The production binary
  (`make build`) must not link `internal/devtools`. The only wiring is
  `cmd/agent-sudo/devtools.go` (build-tagged). Verify with the usage string: the
  production build lists no `root-smoke` / `launchd-dev`.

## What is NOT a guarantee
- This does not defend a fully compromised user account, and cannot stop a direct
  `sudo` bypass if the agent already holds broad sudoers access or cached creds.
- `agent-sudo self-test` (`internal/selftest`) reports detectable residual bypass
  risk; keep its checks honest rather than asserting safety the code can't prove.

## Tests that guard these
`internal/broker/path_security_test.go` and `internal/cli/cli_test.go` cover the
rootless negative cases; the privileged harness adds root-owned checks. Any change
to a control above needs a matching negative test — see `docs/testcases.md` for the
acceptance matrix (weak reason, shell string, TOCTOU swap, hash mismatch, symlink,
writable parent, env injection, output secrets).
