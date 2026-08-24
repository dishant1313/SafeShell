# SafeShell Phase Notes

## Phase 1: Foundations & Environment

### Deviations & Decisions

- **Python 3.12 satisfies >=3.11**: System Python is 3.12.3; the project requires >=3.11. No compatibility issues.
- **Aya deferred to Phase 7**: eBPF tooling (aya/aya-bpf) will be added when the monitor module is implemented.
- **Params kept `serde_json::Value` until Phase 6**: The Rust `CoreRequest.params` field uses `serde_json::Value` rather than typed structs; concrete types will be introduced as operations are implemented.
- **state.py Python impl replaced by Rust collector via IPC in Phase 6**: The Python `state.py` stub exists for the interface, but the actual state collection will be performed by the Rust binary via IPC.

## Phase 3: Risk Classification (Rules + XGBoost)

### Deviations & Decisions

- **Removed Pandas from `train_risk_model.py`**: A non-goal was to avoid introducing new dependencies beyond pinned requirements (`requirements.txt`). Pandas was replaced with the built-in `csv` module for loading the generated synthetic risk corpus.
- **Rules-only Critical Tier**: Critical classifications bypass the XGBoost model completely for fail-closed security.
- **Excluded Critical Rows from Training**: Rows marked as critical are included in the CSV but dropped during XGBoost training so the model strictly predicts fuzzy bounds (Low/Medium/High).
- **Target File Count Approximation**: `target_file_count` caps at 5,000 files to prevent unbounded processing during parsing.
- **Thresholds**: Probabilities from XGBoost `s = P(high) + 0.5*P(medium)` are strictly bracketed at `0.65` (High) and `0.35` (Medium).
- **Seeds**: Random seeding was set to `1337` for corpus generation and `42` for XGBoost stratified splits to ensure determinism.
- **Denylist Location**: The denylist is kept directly within `safeshell/classifier.py` logic rather than configurable rules to enforce fail-closed design.

## Phase 5: Planning Stack Completed
- **Templates**: Deterministic logic for `mv`, `cp`, `rm`, `touch`, `chmod`, `chown`, `mkdir`, `ln`, `systemctl` implemented in `safeshell/templates.py`.
- **RAG**: Seeded mock manpages and integrated vector retrieval for unknown commands in `safeshell/rag.py`.
- **AI Planner**: Constrained LLM generation integrated with N-sample candidate selection in `safeshell/planner.py`.
- **Validator**: Validates JSON schema adherence, closed-vocabulary rollback actions, and applies Ed25519 signatures in `safeshell/validator.py`.
- **Cascade**: `safeshell/planner_cascade.py` orchestrates the hierarchy from templates down to AI, enforcing fail-closed constraints.
- **Acceptance Tests**: All tests passed (D1-D7).

## Phase 10 Updates
- Overhauled the CLI to use Typer and Rich, providing a rich, interactive TUI.
- Implemented the learning loop (safeshell/learn.py) that tokenizes paths and populates the RAG database, including quarantine rules after multiple simulation failures.
- Added replay and what-if capabilities to detect state drift using pre-state hashing (safeshell/replay.py).
- Added an IsolationForest-based anomaly detection engine (safeshell/anomaly.py) to flag unusual activity patterns.
- Created `safeshell/explain.py` for deterministic plain-English rollback explanations.
- Added comprehensive self-test and benchmark suites to validate performance and correctness constraints.
- Generated 9 honest documentation files outlining architecture, benchmarks, and threat models.

**Final Acceptance Verification (D1-D9)**:
- D1/D2/D5 (Product, TUI, Explain): Implemented in `cli.py` and `explain.py`.
- D3 (Replay): Implemented in `replay.py`.
- D4 (Selftest): Implemented in `selftest.py` with 24 cases (some mocked where environmental dependencies exist).
- D6 (Benchmarks): Implemented in `bench.py` tracking end-to-end latency.
- D7 (Anomaly): Implemented in `anomaly.py` via IsolationForest.
- D8 (Corpus): Added `data/adversarial_corpus.json` and updated tests.
- D9 (Docs): Generated all required markdown documents.
