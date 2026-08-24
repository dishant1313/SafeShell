<div align="center">
  <h1>🛡️ SafeShell</h1>
  <p><strong>A Safer Shell — Every system effect, undoable.</strong></p>
</div>

SafeShell is a verified transactional command execution framework for Linux. It acts as an invisible safety net over your standard terminal. 

> **Not a safer folder. A safer shell.** <br>
> AI proposes. Simulation decides. SafeShell remembers — and learns.

Whenever you attempt a destructive command (like `rm`, `mv`, `chmod`, `curl`), SafeShell intercepts it, evaluates the blast radius, generates a deterministic rollback plan using AI, and simulates it in an isolated sandbox. If it's safe, you can approve the transaction, knowing you can easily undo it later. 

---

## ✨ Features

- **Interactive REPL (`safeshell_repl.py`)**: Drop into a fully interactive bash-like shell that automatically wraps every command in SafeShell's protection.
- **Fail-Closed Design**: No snapshot, invalid plan, or divergence = block execution.
- **Deterministic Templates First**: It relies on safe, known rollback templates whenever possible. 
- **AI Fallback**: When templates fail, an Ollama-powered local AI model (`safeshell-planner-3b`) generates custom JSON rollback plans.
- **Rust Core & EBPF Sandboxing**: The `safeshell-core` backend simulates commands at the system level to verify safety and capture exact state changes.

## 🚀 Quickstart

We provide an automated setup script that installs system dependencies, Rust, Python virtual environments, and pulls the local AI models via Ollama.

```bash
# 1. Clone the repository
git clone https://github.com/dishant1313/SafeShell.git
cd SafeShell

# 2. Run the quickstart setup
bash quickstart.sh
```

## 💻 Usage

### 1. Interactive REPL (Recommended)
You don't need to learn a new CLI syntax. Just launch our interactive shell:
```bash
source .venv/bin/activate
./scripts/safeshell_repl.py
```
*Your prompt will change to `safeshell$ `. Navigate with `cd` and `ls` normally. Any destructive command will automatically be intercepted and protected.*

### 2. Standard CLI Usage
If you prefer running single commands, use the `safeshell run` prefix:

```bash
# Analyze command risk & blast radius
safeshell analyze "rm -rf /tmp/build"

# Generate verified rollback plan
safeshell plan "mv config.yaml backup.yaml"

# Dry-run transaction and view plain-English explanation
safeshell whatif "chown -R root:root /var/www"

# Execute a transactional command
safeshell run "mv old.txt new.txt"

# Undo a transaction
safeshell undo <TXN_ID>

# View cryptographic audit ledger
safeshell ledger --verify
```

## 🛠️ Architecture

SafeShell bridges Python and Rust using IPC:
- **Python CLI / Planner**: Parses arguments, runs RAG, and queries local LLMs to formulate a plan.
- **Rust Core**: Executes commands in an `overlayfs` sandbox, verifies rollbacks, and journals cryptographic transactions.

```
safeshell/
├── scripts/            # Setup scripts, REPL, Human Checks
├── safeshell/          # Python Application (CLI, RAG, Planners)
├── core/               # Rust Core Binary (Sandbox, EBPF, IPC)
├── tests/              # Extensive test suite
└── config/             # SafeShell Policies
```

## 📝 License
MIT
