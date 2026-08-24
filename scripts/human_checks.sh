#!/usr/bin/env bash
# SafeShell Human Acceptance & Sudo Verification Script
# Required by Phase 11 Corrigendum (G1, G6, G7, G10)
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "========================================================"
echo "        SafeShell Human & Sudo Acceptance Suite        "
echo "========================================================"
echo ""

# Ensure virtual environment exists
if [ ! -f ".venv/bin/python" ]; then
    echo "[-] Virtualenv not found. Run 'make setup' first."
    exit 1
fi

echo "--- [Check 1/5] Full Test Suite (with Root / CAP_SYS_ADMIN) ---"
echo "Running: sudo .venv/bin/python -m pytest tests/ -v"
echo "--------------------------------------------------------"
sudo .venv/bin/python -m pytest tests/ -v
echo "[+] Check 1 Passed."
echo ""

echo "--- [Check 2/5] SafeShell Self-Test Battery ---"
echo "Running: sudo .venv/bin/python -m safeshell selftest"
echo "--------------------------------------------------------"
sudo .venv/bin/python -m safeshell selftest
echo "[+] Check 2 Passed."
echo ""

echo "--- [Check 3/5] Key File Permissions (G6) ---"
echo "Running: stat -c %a .safeshell/keys/planner_key.ed25519"
echo "--------------------------------------------------------"
KEY_PERMS=$(stat -c %a .safeshell/keys/planner_key.ed25519 2>/dev/null || echo "not_found")
echo "Key file permissions: $KEY_PERMS"
if [ "$KEY_PERMS" = "600" ]; then
    echo "[+] Check 3 Passed (600)."
else
    echo "[!] Warning: Expected 600, got $KEY_PERMS"
fi
echo ""

echo "--- [Check 4/5] Denylist Escape Hatch Denial (G6) ---"
echo "Running: safeshell run 'rm -rf /' --accept-irreversible --yes"
echo "--------------------------------------------------------"
set +e
.venv/bin/python -m safeshell run "rm -rf /" --accept-irreversible --yes
EXIT_CODE=$?
set -e
echo "Exit code: $EXIT_CODE"
if [ "$EXIT_CODE" -eq 2 ]; then
    echo "[+] Check 4 Passed (Denylist cannot be bypassed with flags, exited with 2)."
else
    echo "[-] Check 4 Failed: Expected exit code 2, got $EXIT_CODE."
fi
echo ""

echo "--- [Check 5/5] Fast Path Lazy Loading (Ollama stopped) (G6) ---"
echo "Temporarily stopping ollama to test deterministic fast path (<0.5s)..."
set +e
sudo systemctl stop ollama 2>/dev/null || pkill ollama 2>/dev/null || true
echo "Timing: time .venv/bin/python -m safeshell plan 'mv a b'"
time .venv/bin/python -m safeshell plan "mv a b"
PLAN_EXIT=$?
echo "Restarting ollama service..."
sudo systemctl start ollama 2>/dev/null || nohup ollama serve >/dev/null 2>&1 &
set -e
if [ "$PLAN_EXIT" -eq 0 ]; then
    echo "[+] Check 5 Passed (Fast path succeeded without LLM dependency)."
else
    echo "[-] Check 5 Failed: plan exited with $PLAN_EXIT."
fi
echo ""

echo "========================================================"
echo "               All Human Checks Complete                "
echo "========================================================"
