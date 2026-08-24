import json
import os
import subprocess

import pytest


@pytest.mark.integration
def test_corpus_train():
    base_dir = os.path.dirname(os.path.dirname(__file__))

    # Run data generator
    gen_script = os.path.join(base_dir, "data", "gen_risk_corpus.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = base_dir
    res = subprocess.run(
        [".venv/bin/python", gen_script], cwd=base_dir, capture_output=True, text=True, env=env
    )
    assert res.returncode == 0

    # Run trainer
    train_script = os.path.join(base_dir, "scripts", "train_risk_model.py")
    res = subprocess.run(
        [".venv/bin/python", train_script], cwd=base_dir, capture_output=True, text=True, env=env
    )
    assert res.returncode == 0
    assert "Accuracy:" in res.stdout

    # Verify model
    model_path = os.path.join(base_dir, "models", "risk_model.joblib")
    assert os.path.exists(model_path)

    size_bytes = os.path.getsize(model_path)
    assert size_bytes < 1024 * 1024, f"Model size {size_bytes} >= 1MB"

    # Verify metadata
    meta_path = os.path.join(base_dir, "models", "risk_model_meta.json")
    assert os.path.exists(meta_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)
        assert meta["accuracy"] >= 0.90
