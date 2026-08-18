# SafeShell

**Verified transactional command execution framework for Linux.**

> AI proposes. Policy restricts. Simulation verifies. Snapshots protect.
> Audit records everything. And the system learns.

## Philosophy

- AI proposes but **never decides** — every AI output is schema-validated, policy-checked, and simulation-tested
- **Deterministic templates first**; LLM is a last resort
- **Fail-closed everywhere** — no snapshot, invalid plan, or divergence → block or escalate

## Quick Start

```bash
make setup    # Install deps, pull models, create venv
make build    # Compile Rust core binary
make test     # Run all tests
make lint     # Lint Python (ruff) + Rust (clippy)
```

## Repository Structure

```
safeshell/
├── scripts/
│   └── setup_env.sh
├── safeshell/
│   ├── __init__.py
│   ├── __main__.py
│   ├── schemas.py          # Frozen v3 contract
│   ├── config.py
│   ├── executor.py         # IPC bridge to Rust
│   ├── parser.py           # Phase 2
│   ├── classifier.py       # Phase 3
│   ├── brs.py              # Phase 4
│   ├── state.py            # Phase 4
│   ├── templates.py        # Phase 5
│   ├── rag.py              # Phase 5
│   ├── planner.py          # Phase 5
│   ├── validator.py        # Phase 5
│   ├── policy.py           # Phase 4
│   ├── causal.py           # Phase 9
│   ├── simulation.py       # Phase 8
│   ├── recovery.py         # Phase 9
│   ├── replay.py           # Phase 10
│   ├── learn.py            # Phase 10
│   ├── anomaly.py          # Phase 10
│   ├── ledger.py           # Phase 9
│   ├── explain.py          # Phase 10
│   └── cli.py              # Phase 10
├── core/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── ipc.rs
│       ├── ops.rs
│       ├── sandbox.rs      # Phase 7
│       ├── snapshot.rs     # Phase 6
│       ├── state.rs        # Phase 6
│       ├── monitor.rs      # Phase 7
│       └── journal.rs      # Phase 9
├── tests/
│   ├── conftest.py
│   ├── test_schemas.py
│   ├── test_ipc.py
│   └── test_smoke.py
├── models/
│   └── Modfile.planner-3b
├── config/
├── data/
├── docs/
├── demo/
├── .safeshell/
│   ├── snapshots/
│   └── txns/
├── requirements.txt
├── pyproject.toml
├── Makefile
├── .gitignore
├── LICENSE
├── README.md
└── PHASE_NOTES.md
```

## 10-Phase Roadmap

- [x] **Phase 1**: Foundations & Environment
- [ ] **Phase 2**: Command Parser
- [ ] **Phase 3**: Risk Classifier
- [ ] **Phase 4**: BRS, State Collector, Policy Engine
- [ ] **Phase 5**: Templates, RAG, AI Planner, Validator
- [ ] **Phase 6**: Snapshots & State (Rust)
- [ ] **Phase 7**: Sandbox & eBPF Monitor (Rust)
- [ ] **Phase 8**: Simulation Engine
- [ ] **Phase 9**: Ledger, Recovery, Causal Undo
- [ ] **Phase 10**: TUI, Replay, Learning, Explain, Anomaly

## License

MIT
