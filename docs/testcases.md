# Test Cases: agent-sudo

Date: 2026-06-04

## Scope

These test cases cover the intended `agent-sudo` product described in
`README.md` and `docs/broker-design.md`. Because the current repo is
design-only, this file is an acceptance test plan for the implementation to be
built.

Priority:

- P0: release blocker for any root broker
- P1: required before broad beta
- P2: required before large-scale general availability

Execution layers:

- Unit: pure parser, policy, validation, and serialization tests
- Rootless integration: CLI to user-mode mock broker over Unix socket
- Privileged integration: disposable VM or isolated test machine only
- Scale: stress, concurrency, update, retention, and fleet-style tests
- Manual UX: approval, recovery, and user comprehension tests

## Functional CLI And Broker Contract

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-FUNC-001 | P0 | Unit | Parse `agent-sudo request --reason "x" -- /bin/echo hello` | Request contains executable `/bin/echo`, argv `["hello"]`, reason, cwd, uid metadata |
| AS-FUNC-002 | P0 | Unit | Omit `--` separator before command | CLI rejects with stable usage error and no broker request |
| AS-FUNC-003 | P0 | Unit | Use relative executable `brew install jq` | Rejected before execution unless policy explicitly permits path resolution |
| AS-FUNC-004 | P0 | Unit | Use absolute executable with empty argv | Policy engine evaluates exact executable and empty argv safely |
| AS-FUNC-005 | P0 | Rootless integration | CLI connects to mock broker Unix socket | Request/response round trip works without root |
| AS-FUNC-006 | P0 | Rootless integration | Broker unavailable | CLI returns stable retryable infrastructure error, no fallback to sudo |
| AS-FUNC-007 | P0 | Rootless integration | Broker returns `REASON_INVALID` JSON | CLI prints human-readable guidance and preserves machine-readable fields when requested |
| AS-FUNC-008 | P0 | Rootless integration | Broker returns stdout, stderr, and exit code | CLI exits with command exit code and bounded output |
| AS-FUNC-009 | P1 | Unit | Unknown response field from newer broker | Older CLI ignores unknown field and preserves core behavior |
| AS-FUNC-010 | P1 | Unit | Older broker lacks optional field | Newer CLI handles missing optional field without panic |
| AS-FUNC-011 | P1 | Rootless integration | Request includes session id | Audit groups request under session without granting extra privilege |
| AS-FUNC-012 | P1 | Rootless integration | Agent retries after retryable denial | New request gets new request id and original denial remains audited |

## Policy, Reason, And Risk Classification

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-POL-001 | P0 | Unit | Weak reason `sudo` | `REASON_INVALID`, retryable guidance |
| AS-POL-002 | P0 | Unit | Empty reason | `REASON_INVALID` |
| AS-POL-003 | P0 | Unit | Very long reason beyond configured limit | `REASON_INVALID`, no log overflow |
| AS-POL-004 | P0 | Unit | Reason says validate, command installs package | `REASON_INVALID` or `POLICY_MISMATCH` |
| AS-POL-005 | P0 | Unit | Unknown executable | Default deny with `REVIEW_REQUIRED` or `POLICY_MISMATCH`, no execution |
| AS-POL-006 | P0 | Unit | Known executable with disallowed arg | Default deny |
| AS-POL-007 | P0 | Unit | `visudo -c -f /etc/sudoers.d/lima` under exact policy | Approved when client and path scope match |
| AS-POL-008 | P0 | Unit | `visudo -f /etc/sudoers.d/lima` missing `-c` | Denied as mutation-capable or policy mismatch |
| AS-POL-009 | P0 | Unit | `brew install jq` under package policy | Classified `install_or_update`, approval required if configured |
| AS-POL-010 | P0 | Unit | `brew tap` or `brew install --cask` under simple install policy | Denied unless explicitly allowed |
| AS-POL-011 | P0 | Unit | `chmod -R /` | Classified high-risk/destructive and denied without exact policy and approval |
| AS-POL-012 | P0 | Unit | `diskutil eraseDisk` | Classified destructive and requires explicit high-risk policy and approval |
| AS-POL-013 | P0 | Unit | `launchctl bootout` | Classified service control/high risk |
| AS-POL-014 | P0 | Unit | Policy rule contains invalid schema | Broker refuses to activate policy |
| AS-POL-015 | P0 | Unit | Policy file has broad wildcard executable | Validation fails unless explicitly marked raw high-risk |
| AS-POL-016 | P1 | Unit | Policy schema migration from old version | Migration is explicit, audited, and reversible |
| AS-POL-017 | P1 | Unit | Duplicate policy ids | Broker rejects policy load |
| AS-POL-018 | P1 | Unit | Conflicting policies match same request | Deterministic decision, safest rule wins, conflict audited |
| AS-POL-019 | P1 | Unit | Policy requires cwd scope and request cwd differs | Denied |
| AS-POL-020 | P1 | Unit | Policy requires exact target path and symlink resolves elsewhere | Denied |

## Command Execution Security

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-SEC-001 | P0 | Unit | Request `/bin/sh -c "id"` | Denied unless exact shell policy exists |
| AS-SEC-002 | P0 | Unit | Request `/bin/bash -c "curl ..."` | Denied unless exact shell policy exists |
| AS-SEC-003 | P0 | Unit | Arg contains pipe character | Denied if policy disallows shell-like metacharacters |
| AS-SEC-004 | P0 | Unit | Arg contains redirection `>` | Denied if policy disallows shell-like metacharacters |
| AS-SEC-005 | P0 | Unit | Arg contains command substitution `$()` | Denied if policy disallows shell-like metacharacters |
| AS-SEC-006 | P0 | Unit | Arg contains backticks | Denied if policy disallows shell-like metacharacters |
| AS-SEC-007 | P0 | Unit | Environment includes `DYLD_INSERT_LIBRARIES` | Broker strips or denies before execution |
| AS-SEC-008 | P0 | Unit | Environment includes `LD_PRELOAD` | Broker strips or denies before execution |
| AS-SEC-009 | P0 | Unit | Environment overrides `PATH` | Execution still uses absolute executable and sanitized env |
| AS-SEC-010 | P0 | Unit | Environment includes package-manager config that changes install source | Stripped or requires explicit policy |
| AS-SEC-011 | P0 | Privileged integration | Request times out | Process terminated, timeout audited, no orphan privileged child |
| AS-SEC-012 | P0 | Privileged integration | Command writes enormous stdout | Output capped, command handled without memory exhaustion |
| AS-SEC-013 | P0 | Privileged integration | Command forks child processes | Timeout and cleanup include child process group where supported |
| AS-SEC-014 | P0 | Privileged integration | Command exits non-zero after partial mutation | Exit code and partial-failure status audited |
| AS-SEC-015 | P1 | Unit | Unicode homoglyph in path or policy id | Canonicalization prevents policy confusion |
| AS-SEC-016 | P1 | Unit | Null byte in path or argv field | Request rejected during validation |
| AS-SEC-017 | P1 | Unit | Extremely many argv entries | Request rejected or bounded without resource exhaustion |
| AS-SEC-018 | P1 | Unit | Extremely long single argv entry | Request rejected or bounded without resource exhaustion |
| AS-SEC-019 | P1 | Privileged integration | Request tries to execute file on network share | Denied unless policy allows filesystem source |
| AS-SEC-020 | P1 | Privileged integration | Request cwd is deleted before execution | Broker fails safely and audits error |

## Client Trust And Local Boundary

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-TRUST-001 | P0 | Rootless integration | Unknown client token | `CLIENT_NOT_TRUSTED`, no execution |
| AS-TRUST-002 | P0 | Rootless integration | Trusted client path changed after enrollment | Broker detects mismatch or requires re-enrollment |
| AS-TRUST-003 | P0 | Rootless integration | Process name spoofed to `codex` | Not trusted by name alone |
| AS-TRUST-004 | P0 | Privileged integration | Non-owner local user connects to production socket | Permission denied before request processing |
| AS-TRUST-005 | P0 | Privileged integration | Same user invokes CLI outside configured agent | Denied or requires approval according to threat model |
| AS-TRUST-006 | P0 | Privileged integration | Socket permissions are group/world writable | `self-test` fails and broker refuses production mode |
| AS-TRUST-007 | P1 | Privileged integration | Enrolled client binary is replaced | Code signature or path metadata mismatch triggers re-enrollment |
| AS-TRUST-008 | P1 | Privileged integration | Parent process ancestry is unavailable | Broker degrades to safer decision, not silent trust |
| AS-TRUST-009 | P1 | Privileged integration | Multiple users installed on same Mac | One user's trust config cannot authorize another user's requests |
| AS-TRUST-010 | P1 | Privileged integration | Fast user switching while broker active | Socket and policy isolation remain correct |
| AS-TRUST-011 | P1 | Unit | Enrollment token file has weak permissions | Broker rejects token and `self-test` reports issue |
| AS-TRUST-012 | P1 | Unit | Trust config edited by non-root where root policy required | Broker rejects config or marks client untrusted |

## Artifact And Fetch Workflow

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-ART-001 | P0 | Rootless integration | Fetch HTTPS URL with correct checksum | Artifact stored by content hash and audited |
| AS-ART-002 | P0 | Rootless integration | Fetch URL with wrong checksum | `ARTIFACT_UNVERIFIED`, artifact not runnable |
| AS-ART-003 | P0 | Rootless integration | Fetch HTTP URL | Denied unless policy explicitly allows |
| AS-ART-004 | P0 | Rootless integration | HTTPS redirects to unallowlisted host | Denied |
| AS-ART-005 | P0 | Rootless integration | Response exceeds size limit | Fetch aborted and audited |
| AS-ART-006 | P0 | Rootless integration | Content type disallowed by policy | Fetch denied |
| AS-ART-007 | P0 | Rootless integration | Import local script under world-writable parent | Denied |
| AS-ART-008 | P0 | Rootless integration | Import symlink to sensitive path | Denied unless explicit symlink policy exists |
| AS-ART-009 | P0 | Rootless integration | Inspect artifact, then mutate original source file | Running artifact uses stored content hash, not mutated source |
| AS-ART-010 | P0 | Rootless integration | Stored artifact hash changes before run | `ARTIFACT_UNVERIFIED` |
| AS-ART-011 | P0 | Rootless integration | Artifact contains second-stage download | Classified `network_at_runtime` and requires approval |
| AS-ART-012 | P0 | Rootless integration | Artifact invokes package manager with hooks | Classified hook-capable and requires approval |
| AS-ART-013 | P1 | Rootless integration | Artifact path uses hardlink ambiguity | Denied or resolved to stored content only |
| AS-ART-014 | P1 | Rootless integration | Artifact store is writable by group/world | `self-test` fails and run is denied |
| AS-ART-015 | P1 | Rootless integration | Import binary artifact | Requires binary policy and logs hash |
| AS-ART-016 | P1 | Rootless integration | Artifact run passes args containing shell syntax | Args validated as argv and denied if policy disallows |
| AS-ART-017 | P1 | Scale | Many concurrent fetches of same artifact | Single stored content object, no corruption |
| AS-ART-018 | P1 | Scale | Fetch server slow or hangs | Timeout, cleanup, and audit event |

## Audit Logging

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-AUD-001 | P0 | Unit | Approved request event | JSONL includes schema version, request id, ts, client, cwd, reason, executable, argv, decision, policy id, effect |
| AS-AUD-002 | P0 | Unit | Denied request event | Denial is logged with reason code and no execution fields claiming success |
| AS-AUD-003 | P0 | Unit | Artifact run event | Logs artifact id and sha256 |
| AS-AUD-004 | P0 | Unit | Command prints fake token | Full secret is not stored; hash/tail/redaction policy applies |
| AS-AUD-005 | P0 | Unit | Environment contains secrets | Full environment is never logged |
| AS-AUD-006 | P0 | Privileged integration | Agent user attempts to edit production audit log | Permission denied |
| AS-AUD-007 | P0 | Privileged integration | Disk nearly full | Broker fails safely, preserves existing logs, reports actionable error |
| AS-AUD-008 | P0 | Privileged integration | Broker killed mid-request | Audit remains parseable and indicates interrupted/unknown result |
| AS-AUD-009 | P1 | Scale | Millions of local events over retention period | Rotation keeps disk bounded and query remains usable |
| AS-AUD-010 | P1 | Unit | Unknown future audit field | Parser tools ignore unknown fields |
| AS-AUD-011 | P1 | Unit | Clock jumps backward | Audit ordering still includes monotonic or sequence metadata |
| AS-AUD-012 | P1 | Unit | Timezone changes | Timestamps remain unambiguous |
| AS-AUD-013 | P1 | Manual UX | `agent-sudo audit show <request-id>` for denied request | User sees exact reason and no misleading success |
| AS-AUD-014 | P1 | Manual UX | Redacted support bundle export | Sensitive fields omitted by default |

## Sessions, Approval, And UX

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-UX-001 | P0 | Unit | Session id omitted | Request evaluated independently |
| AS-UX-002 | P0 | Unit | Unknown session id | `SESSION_INVALID` or no extra authority |
| AS-UX-003 | P0 | Unit | Client A uses Client B session id | Denied |
| AS-UX-004 | P0 | Unit | Expired approval lease | Denied or approval required again |
| AS-UX-005 | P0 | Manual UX | High-risk approval prompt | Shows executable, argv, cwd, policy id, effect, target, client, reason, and risk |
| AS-UX-006 | P0 | Manual UX | Destructive operation approval | Requires explicit confirmation beyond one keystroke |
| AS-UX-007 | P0 | Manual UX | Repeated prompt spam | Rate-limited with deny-session option |
| AS-UX-008 | P1 | Manual UX | User denies approval | Agent receives stable denial and next-step guidance |
| AS-UX-009 | P1 | Manual UX | User approves exact scoped lease | Later matching request succeeds only within exact lease scope |
| AS-UX-010 | P1 | Manual UX | Later request changes target under lease | Approval required again |
| AS-UX-011 | P1 | Manual UX | Terminal cannot display interactive approval | Fails safely or uses configured GUI approval path |
| AS-UX-012 | P2 | Manual UX | Non-English locale | CLI remains parseable and logs stable machine codes |

## Installation, Update, And Recovery

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-INST-001 | P0 | Privileged integration | Fresh install on clean Mac | Binary, launchd service, socket dir, policy dir, and log dir installed with correct ownership and modes |
| AS-INST-002 | P0 | Privileged integration | Re-run install | Idempotent or clearly reports already installed |
| AS-INST-003 | P0 | Privileged integration | Installer checksum mismatch | Install aborts before writing privileged files |
| AS-INST-004 | P0 | Privileged integration | Unsigned binary in production install | Install aborts if signatures are required |
| AS-INST-005 | P0 | Privileged integration | Update interrupted mid-write | Previous working broker remains or rollback succeeds |
| AS-INST-006 | P0 | Privileged integration | Downgrade attempt | Denied unless explicit recovery mode |
| AS-INST-007 | P0 | Privileged integration | Policy migration fails | Old policy remains active and failure is audited |
| AS-INST-008 | P0 | Privileged integration | Uninstall broker | Service stopped, socket removed, binaries removed, logs handled by explicit choice |
| AS-INST-009 | P0 | Privileged integration | Broken policy prevents broker start | Recovery command can validate and restore last-known-good policy |
| AS-INST-010 | P1 | Privileged integration | Machine reboots after install | Broker starts with correct socket permissions |
| AS-INST-011 | P1 | Privileged integration | OS update occurs | Broker either continues working or reports clear remediation |
| AS-INST-012 | P1 | Scale | Canary update to small cohort | Version, failure rate, rollback, and compatibility signals are captured |
| AS-INST-013 | P1 | Scale | Bad release is rolled back | Signed rollback path works without leaving stale root service |
| AS-INST-014 | P2 | Manual UX | User manually deletes binary but launchd plist remains | `self-test` identifies broken install and repair path |

## Concurrency, Scale, And Reliability

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-SCALE-001 | P0 | Scale | Two package installs start concurrently | Broker serializes or rejects conflicting second request |
| AS-SCALE-002 | P0 | Scale | Policy edit while command executes | Active request uses stable policy snapshot; edit is audited separately |
| AS-SCALE-003 | P0 | Scale | Broker update while command executes | Update waits, cancels safely, or refuses until idle |
| AS-SCALE-004 | P0 | Scale | Network change request while remote session depends on network | Approval prompt highlights connectivity risk |
| AS-SCALE-005 | P0 | Scale | Disk operation targets mounted active disk | Destructive classification and approval gate |
| AS-SCALE-006 | P1 | Scale | 1000 denied requests in a minute | Broker remains responsive, rate limits noisy client |
| AS-SCALE-007 | P1 | Scale | 100 concurrent clients request read-only validation | Broker handles load or queues with clear status |
| AS-SCALE-008 | P1 | Scale | Long-running command and short command queued | Status shows queue and timeout behavior is predictable |
| AS-SCALE-009 | P1 | Scale | Client disconnects mid-command | Broker completes or cancels according to policy and audits result |
| AS-SCALE-010 | P1 | Scale | Machine sleeps during command | Resume behavior is audited and does not leave stale locks |
| AS-SCALE-011 | P1 | Scale | Artifact store grows beyond quota | Cleanup policy preserves referenced artifacts and reports space issue |
| AS-SCALE-012 | P1 | Scale | Audit log rotation during active write | No event loss or malformed JSONL |
| AS-SCALE-013 | P2 | Scale | Millions of installs check for updates | Update endpoint and client backoff avoid thundering herd |
| AS-SCALE-014 | P2 | Scale | Many users behind proxy or captive portal | Update/fetch failures are clear and do not weaken verification |

## Platform Matrix

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-PLAT-001 | P0 | Privileged integration | macOS Apple Silicon with Homebrew in `/opt/homebrew` | Policies resolve expected paths |
| AS-PLAT-002 | P0 | Privileged integration | macOS Intel with Homebrew in `/usr/local` | Policies resolve expected paths |
| AS-PLAT-003 | P0 | Privileged integration | macOS launchd service restart | Socket recreated with correct owner/mode |
| AS-PLAT-004 | P0 | Privileged integration | Managed Mac blocks unsigned helpers | Installer fails safely with remediation |
| AS-PLAT-005 | P1 | Privileged integration | User home path contains spaces | CLI, audit, and policy handling remain correct |
| AS-PLAT-006 | P1 | Privileged integration | FileVault or locked keychain state after reboot | Broker does not depend on unavailable user secrets for root startup |
| AS-PLAT-007 | P1 | Privileged integration | SIP-protected paths | Broker denies or surfaces OS permission failure safely |
| AS-PLAT-008 | P1 | Privileged integration | Multiple shells and PATH setups | Agent instruction still uses absolute command paths |
| AS-PLAT-009 | P1 | Privileged integration | Network home directory | Unsafe writable or remote paths are handled by policy |
| AS-PLAT-010 | P1 | Privileged integration | Linux support if added | systemd, socket credentials, SELinux/AppArmor, and distro package managers tested separately |
| AS-PLAT-011 | P2 | Manual UX | Accessibility with screen reader for approvals | High-risk prompt can be understood and denied safely |
| AS-PLAT-012 | P2 | Manual UX | Small terminal window | CLI output remains readable and does not hide decision code |

## Agent Integration And Bypass Resistance

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-AGENT-001 | P0 | Manual UX | Generate Codex integration instructions | Instructs agent to use `agent-sudo request` and avoid direct `sudo` |
| AS-AGENT-002 | P0 | Manual UX | Generate Claude Code integration instructions | Same narrow command contract |
| AS-AGENT-003 | P0 | Manual UX | Agent receives `REASON_INVALID` | Agent can retry with better reason, not raw sudo |
| AS-AGENT-004 | P0 | Manual UX | Agent receives `REVIEW_REQUIRED` | Agent stops or asks user; does not bypass |
| AS-AGENT-005 | P0 | Privileged integration | Cached sudo credentials exist | `self-test` warns that direct sudo bypass may be possible |
| AS-AGENT-006 | P0 | Privileged integration | Broad passwordless sudoers rule exists for agent user | `self-test` warns and docs mark broker audit as incomplete |
| AS-AGENT-007 | P1 | Manual UX | Nested agent launched from trusted agent | Broker treats nested requester according to explicit trust policy |
| AS-AGENT-008 | P1 | Manual UX | Agent attempts `curl \| sudo sh` | Integration and policy reject; staged artifact flow suggested |
| AS-AGENT-009 | P1 | Manual UX | Agent needs unsupported privileged action | Broker returns stable review-required path without suggesting unsafe command |
| AS-AGENT-010 | P2 | Manual UX | Project-specific agent guide includes snippet | Snippet is short, deterministic, and does not expose broad policy |

## Privacy, Support, And Compliance

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-PRIV-001 | P0 | Unit | Audit event contains project path | Path is expected locally; support export can redact |
| AS-PRIV-002 | P0 | Unit | Command output includes API key pattern | Redacted or omitted from full log |
| AS-PRIV-003 | P1 | Manual UX | User exports support bundle | Bundle lists included files and redacts secrets by default |
| AS-PRIV-004 | P1 | Manual UX | User disables telemetry | Product has no required telemetry for local operation |
| AS-PRIV-005 | P1 | Scale | Enterprise wants retention policy | Retention can be configured and enforced locally |
| AS-PRIV-006 | P2 | Manual UX | User requests audit deletion on uninstall | Tool offers explicit keep/delete choice with warning |

## Disaster And Abuse Scenarios

| ID | Priority | Layer | Scenario | Expected Result |
| --- | --- | --- | --- | --- |
| AS-DR-001 | P0 | Privileged integration | Malicious same-user process invokes trusted-looking request | Denied or high-risk approval required; event audited |
| AS-DR-002 | P0 | Privileged integration | Malicious process floods approval prompts | Rate-limited and visible in audit |
| AS-DR-003 | P0 | Privileged integration | Broker binary replaced on disk | Signature or ownership check fails and service refuses to run |
| AS-DR-004 | P0 | Privileged integration | Policy file replaced by user-writable symlink | Broker refuses policy load |
| AS-DR-005 | P0 | Privileged integration | Audit path replaced by symlink | Broker refuses to write or repairs safely |
| AS-DR-006 | P0 | Privileged integration | Artifact store path replaced by symlink | Broker refuses artifact operations |
| AS-DR-007 | P0 | Privileged integration | Destructive command approved accidentally | Audit contains exact approval; recovery docs identify last action and rollback note |
| AS-DR-008 | P1 | Privileged integration | Root broker crashes repeatedly | launchd does not spin uncontrolled; `status` reports crash loop |
| AS-DR-009 | P1 | Privileged integration | Host clock is wrong | Request ids and monotonic sequence still support incident ordering |
| AS-DR-010 | P1 | Privileged integration | Local user loses admin rights after install | Broker handles permission errors and documents recovery |

## Minimum Automated Gate For First Root Broker

The first privileged broker release should require these automated suites:

- Unit: AS-FUNC, AS-POL, AS-SEC, AS-AUD, AS-UX parser/session cases.
- Rootless integration: socket contract, default deny, retryable responses,
  artifact store, log writing, output bounds.
- Privileged integration in disposable VM: install, socket permissions, root
  policy ownership, audit ownership, allowed validation command, denied shell
  command, timeout cleanup, update rollback, uninstall.
- Scale: concurrent mutation locks, log rotation, request flood handling,
  update canary simulation.
- Manual UX signoff: high-risk approval comprehension, denial path,
  recovery path, support bundle redaction.
