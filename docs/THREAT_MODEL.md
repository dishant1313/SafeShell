# Threat Model

## Assumptions
- The user has sudo privileges but is prone to mistakes (e.g. `rm -rf /`).
- The LLM can be poisoned, hallucinate, or be actively malicious.
- The system time is monotonic for ledger hashing.

## Mitigations
- **LLM Hallucination**: AI proposes, but Simulation verifies. A bad AI plan simply fails simulation.
- **Privilege Escalation**: Sandbox runs as unprivileged user by default, drops capabilities. 
- **Ledger Tampering**: Cryptographic hash chain prevents undetected retroactive modification.

## Limitations
- eBPF monitoring is mocked in MVP.
- Complex state dependencies across reboots are not captured.
