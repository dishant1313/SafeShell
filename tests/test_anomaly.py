from datetime import datetime, timedelta

from safeshell.anomaly import score_transaction


def test_anomaly_detection(monkeypatch):
    # Mock tail_ledger to return 200 synthetic normal rows
    # Normal: hour between 9 and 17, brs between 0 and 50
    normal_rows = []
    base_time = datetime(2025, 1, 1, 10, 0, 0)

    for i in range(200):
        normal_rows.append(
            {
                "timestamp": (base_time + timedelta(hours=i % 8)).timestamp(),
                "brs": 10 + (i % 40),
                "command": "ls /tmp",
            }
        )

    def mock_tail(n):
        return normal_rows

    monkeypatch.setattr("safeshell.anomaly.tail_ledger", mock_tail)

    # Reset model
    import safeshell.anomaly

    safeshell.anomaly._model = None

    # Normal row evaluation
    normal_row = {
        "timestamp": datetime(2025, 1, 1, 14, 0, 0).timestamp(),
        "brs": 25,
        "command": "ls /tmp",
    }

    assert not score_transaction(normal_row), "Normal row should not be flagged"

    # Anomalous row evaluation (3 AM, BRS 900)
    anomalous_row = {
        "timestamp": datetime(2025, 1, 1, 3, 0, 0).timestamp(),
        "brs": 900,
        "command": "rm -rf /",
    }

    assert score_transaction(anomalous_row), "3am BRS-900 row should be flagged as anomaly"
