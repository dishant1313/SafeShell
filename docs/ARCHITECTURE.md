# SafeShell Architecture

## 1. Parser & Classifier
Determines if a command is simple (rm, mv, chmod) or complex (loops, pipes). 

## 2. Planner Cascade
Templates -> RAG DB -> LLM. 

## 3. Simulation Engine (Rust Core)
Namespace/OverlayFS sandbox, seccomp filters, and eBPF network monitoring (feature-gated for MVP). 

## 4. Validator
Verifies the simulation output against the requested plan, signs with ED25519.

## 5. Executor & Ledger
Executes the signed bundle atomically. If it fails, rolls back. Writes to append-only hashed ledger.

## 6. Learning Loop
Updates RAG DB and templates based on execution success/failure.
