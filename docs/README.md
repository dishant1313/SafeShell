# SafeShell

**Tagline:** "AI proposes. Policy restricts. Simulation verifies. Snapshots protect. Audit records everything. And the system learns."

SafeShell is a verified transactional command execution framework for Linux. It intercepts dangerous terminal commands, proposes a deterministic (or AI-assisted) rollback plan, simulates the effect in a user-namespace overlay sandbox, and enforces strict security policies before any real state mutation occurs. 

## Features
- **Simulation-as-Judge**: Commands are executed in an OverlayFS/Namespace sandbox.
- **Rollback Engine**: Snapshot-driven (LVM/Btrfs-capable) and command-inversion (T1/T2/T3 guarantees).
- **Policy-as-Code**: Strict rules mapped to Blast Radius Score (BRS).
- **Learning Loop**: Fails safely, remembers bad patterns via RAG vector DB, quarantines unsafe templates.
- **Ledger**: Cryptographically hashed execution history.
