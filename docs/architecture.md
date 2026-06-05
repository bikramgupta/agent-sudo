# Architecture (as built)

Agent-facing map of the Stage 1 rootless build. For the design rationale and
threat model see `broker-design.md`; this doc tracks what the code actually does.

## One binary, two roles
- The **CLI** (run by the agent as the normal user) builds a structured request
  and sends it over a Unix socket.
- The **broker** (`agent-sudo broker serve`) owns trust, policy, artifact
  verification, no-shell execution, and audit. Today it runs rootless; in
  production it is meant to run as a root launchd service.

Entrypoint: `cmd/agent-sudo/main.go` → `cli.Run`. The dev harness is wired in
`cmd/agent-sudo/devtools.go` (build tag `devtools`) via `cli.RegisterCommand`.

## Package map
| Package | Responsibility | Key files |
| --- | --- | --- |
| `internal/cli` | Command dispatch + user-facing subcommands | `cli.go` (`Run`), `cli_test.go` |
| `internal/broker` | Server, request processing, execution, privileged path checks | `broker.go` (`process`, `execute`), `path_security.go` |
| `internal/protocol` | Wire types; decision + effect constants | `protocol.go`, `response.go` |
| `internal/policy` | Typed policy match, effect inference, env + reason validation | `policy.go`, `env.go`, `reason.go` |
| `internal/trust` | Client enrollment + executable-hash matching | `trust.go` |
| `internal/peer` | Unix-socket peer identity (cgo on darwin) | `peer_identity_darwin.go`, `peer_identity_other.go` |
| `internal/artifact` | Content-addressed fetch/import/verify store | `artifact.go` |
| `internal/audit` | JSONL schema, logger, bounded redacted capture | `audit.go` |
| `internal/config` | Path resolution + `AGENT_SUDO_*` overrides | `config.go` |
| `internal/fsutil` | Path canonicalization, private-dir checks, hashing | `fsutil.go` |
| `internal/selftest` | Residual-bypass-risk diagnostics | `selftest.go` |
| `internal/devtools` | Disposable root-smoke / launchd-dev harness (`-tags devtools`) | see `internal/devtools/AGENTS.md` |

## Request lifecycle
The broker entrypoint is `Broker.process` in `internal/broker/broker.go`. The
order of checks IS the security contract — preserve it when editing:

1. `ping` / schema version (`SchemaVersion != 1` → `DENIED`).
2. Trust match against the Unix peer (`trust.Match`) → `CLIENT_NOT_TRUSTED`.
3. Required cwd; absolute, null-byte-free executable; argv null-byte and count caps.
4. Artifact path (when `ArtifactID` set): `artifacts.Verify`, request-hash vs stored
   hash, stored-object path match; runtime risk flags → `REVIEW_REQUIRED`.
5. Effect inference (`policy.InferEffect`); reason validation (`policy.ValidateReason`).
6. Policy match (`policy.Match`). No match → shell executable / shell metacharacters
   give `SCOPE_TOO_BROAD`, otherwise `REVIEW_REQUIRED`.
7. Effect-vs-rule consistency, approval mode, `ShellDenied`, `DeniedEnv`.
8. `execute` — argv array only, never a shell; bounded, redacted output capture;
   audit event written.

Decisions/effects are the stable vocabulary in `internal/protocol/protocol.go`
(`DecisionApproved` … `DecisionScopeTooBroad`; `EffectReadOnly` … `EffectDestructive`).

## Paths & configuration
`internal/config/config.go` resolves all on-disk locations, overridable via
`AGENT_SUDO_*` (`AGENT_SUDO_SOCKET`, `AGENT_SUDO_POLICY`, `AGENT_SUDO_TRUST`,
`AGENT_SUDO_AUDIT`, `AGENT_SUDO_ARTIFACT_DIR`, plus `*_CONFIG_DIR/_STATE_DIR/_RUN_DIR`).
Rootless defaults live under `~/.agent-sudo`, `~/.config/agent-sudo`, and
`~/.local/state/agent-sudo` (table in `README.md`).

## When changing X, update Y
- New decision/effect constant → `internal/protocol` **and** the lifecycle list above.
- New subcommand → `cli.Run` switch **and** `printUsage` in `internal/cli/cli.go`.
- New path/env override → `internal/config/config.go` and the README path table.
- Any change to the check order or a security control → `docs/security-invariants.md`.
