---
paths:
  - "internal/broker/**"
  - "internal/policy/**"
  - "internal/artifact/**"
  - "internal/audit/**"
  - "internal/trust/**"
  - "internal/peer/**"
  - "internal/devtools/**"
---
# Security-critical paths
These files are the privilege boundary. Before editing them in this session:
- Use plan mode first; map the change against the invariants in
  `docs/security-invariants.md` and the request-check order in
  `internal/broker/broker.go` `process()` before writing code.
- Do read-only exploration before any cross-package refactor of the request
  lifecycle, trust, or artifact verification — these controls are interdependent.
- Treat a weakened control (reordered checks, broadened policy match, relaxed path
  or hash check, unbounded/unredacted audit output) as a behavior change that needs
  a matching negative test, not a silent edit.
- `internal/devtools` runs as root via disposable harnesses; never repoint it at
  real config/state/audit paths, and re-supervise after rebuilds.
