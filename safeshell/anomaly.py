"""Anomaly Detection Engine (Phase 10)"""

from datetime import datetime, timezone

from sklearn.ensemble import IsolationForest

from safeshell.ledger import tail as tail_ledger

# Cache the model to avoid refitting on every transaction
_model = None
_last_fit = 0


def extract_features(record: dict) -> list:
    """Extract numeric features from a ledger record."""
    try:
        ts = record.get("timestamp", 0)
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts)
        else:
            dt = datetime.fromisoformat(ts)
    except:
        dt = datetime.now(timezone.utc)

    hour = dt.hour
    brs = record.get("brs", 0)

    # In a full implementation we'd compute inter-arrival time and deny rates over a window.
    # For MVP we will just use hour, brs, and a simple command hash to represent family.
    cmd = record.get("command", "")
    family_hash = hash(cmd.split()[0]) % 100 if cmd else 0

    return [hour, brs, family_hash]


def fit_model():
    """Fit the IsolationForest on recent ledger data."""
    global _model, _last_fit

    # Fetch last 1000 records
    records = tail_ledger(1000)
    if len(records) < 50:
        # Not enough data, return
        return

    X = [extract_features(r) for r in records]

    # Fit IsolationForest
    # contamination=0.05 means we expect ~5% anomalies
    _model = IsolationForest(contamination=0.05, random_state=42)
    _model.fit(X)
    _last_fit = datetime.now(timezone.utc).timestamp()


def score_transaction(record: dict) -> bool:
    """Returns True if the transaction is flagged as anomalous."""
    global _model
    if _model is None:
        fit_model()

    if _model is None:
        # Still None (not enough data)
        return False

    X = [extract_features(record)]
    # predict returns 1 for inliers, -1 for outliers
    pred = _model.predict(X)
    return pred[0] == -1
