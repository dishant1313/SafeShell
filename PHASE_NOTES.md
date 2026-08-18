# SafeShell Phase Notes

## Phase 1: Foundations & Environment

### Deviations & Decisions

- **Python 3.12 satisfies >=3.11**: System Python is 3.12.3; the project requires >=3.11. No compatibility issues.
- **Aya deferred to Phase 7**: eBPF tooling (aya/aya-bpf) will be added when the monitor module is implemented.
- **Params kept `serde_json::Value` until Phase 6**: The Rust `CoreRequest.params` field uses `serde_json::Value` rather than typed structs; concrete types will be introduced as operations are implemented.
- **state.py Python impl replaced by Rust collector via IPC in Phase 6**: The Python `state.py` stub exists for the interface, but the actual state collection will be performed by the Rust binary via IPC.
