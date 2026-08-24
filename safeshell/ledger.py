"""Hash-chained append-only ledger for transactions. (Phase 9)"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

LEDGER_PATH = os.path.expanduser("~/.safeshell/ledger.jsonl")


def _get_canonical_json(payload: Dict[str, Any]) -> str:
    # Ensure prev_hash and entry_hash are not in payload when calculating payload hash
    # Actually, the prompt says: entry_hash = sha256(prev_hash + canonical).encode hex
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _init_ledger():
    os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)
    if not os.path.exists(LEDGER_PATH):
        # Open in append mode to create the file and set 0600
        fd = os.open(LEDGER_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)


def append(record: Dict[str, Any]) -> None:
    """Appends a transaction record to the hash-chained ledger."""
    _init_ledger()

    # Extract payload (everything except entry_hash, prev_hash is fine to keep or remove, but schema dictates they are part of it)
    # The prompt: entry_hash = sha256(prev_hash + canonical).encode hex
    # So we compute it and then append to file.

    prev_hash = "0" * 64
    if os.path.exists(LEDGER_PATH) and os.path.getsize(LEDGER_PATH) > 0:
        with open(LEDGER_PATH, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line:
                    try:
                        last_record = json.loads(last_line)
                        prev_hash = last_record.get("entry_hash", prev_hash)
                    except json.JSONDecodeError:
                        pass

    record["prev_hash"] = prev_hash

    # The payload to hash is the record without entry_hash
    payload = {k: v for k, v in record.items() if k != "entry_hash"}
    canonical = _get_canonical_json(payload)

    entry_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
    record["entry_hash"] = entry_hash

    with open(LEDGER_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")

    # Ensure 0600 permissions
    os.chmod(LEDGER_PATH, 0o600)


def verify_ledger() -> Tuple[bool, int]:
    """Verifies the hash chain of the ledger. Returns (is_valid, first_bad_index)."""
    if not os.path.exists(LEDGER_PATH):
        return True, -1

    expected_prev = "0" * 64
    with open(LEDGER_PATH, "r") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, idx

            prev_hash = record.get("prev_hash")
            entry_hash = record.get("entry_hash")

            if prev_hash != expected_prev:
                return False, idx

            payload = {k: v for k, v in record.items() if k != "entry_hash"}
            canonical = _get_canonical_json(payload)
            computed_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()

            if computed_hash != entry_hash:
                return False, idx

            expected_prev = entry_hash

    return True, -1


def get(txn_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a specific transaction record by ID."""
    if not os.path.exists(LEDGER_PATH):
        return None

    with open(LEDGER_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    if record.get("transaction_id") == txn_id:
                        return record
                except json.JSONDecodeError:
                    continue
    return None


def tail(n: int) -> List[Dict[str, Any]]:
    """Retrieves the last n transaction records."""
    if not os.path.exists(LEDGER_PATH):
        return []

    records = []
    with open(LEDGER_PATH, "r") as f:
        lines = f.readlines()
        for line in reversed(lines):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                    if len(records) >= n:
                        break
                except json.JSONDecodeError:
                    continue

    return list(reversed(records))
