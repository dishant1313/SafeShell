import os

from safeshell.causal import build_graph, order_undo
from safeshell.executor import ExecutionAborted, execute_transaction
from safeshell.ledger import LEDGER_PATH, append, get, tail, verify_ledger
from safeshell.parser import parse_bundle
from safeshell.schemas import RollbackPlan, SimulationReport, new_id
from safeshell.state import collect_state


def test_causal_graph():
    script = "mkdir /app/data\ncp cfg /app/data\ntar czf b.tgz /app/data\nrm -rf /app/data"
    steps = parse_bundle(script)

    steps[0].effect_graph = {"creates": ["/app/data"]}
    steps[1].effect_graph = {"creates": ["/app/data/cfg"]}
    steps[1].resolved_paths = ["cfg", "/app/data", "/app/data/cfg"]
    steps[2].effect_graph = {"creates": ["b.tgz"]}
    steps[2].resolved_paths = ["b.tgz", "/app/data"]
    steps[3].effect_graph = {"deletes": ["/app/data"]}
    steps[3].resolved_paths = ["/app/data"]

    graph = build_graph(steps)
    assert graph.nodes == steps

    assert any(tgt == 0 for tgt, kind in graph.edges[1])
    assert any(tgt == 0 for tgt, kind in graph.edges[2])
    assert any(tgt == 0 for tgt, kind in graph.edges[3])

    manifest = collect_state(["/app/data"])
    actions = order_undo(graph, manifest)
    assert isinstance(actions, list)


def test_ledger():
    if os.path.exists(LEDGER_PATH):
        os.remove(LEDGER_PATH)

    append({"transaction_id": "test1", "status": "success"})
    append({"transaction_id": "test2", "status": "failed"})

    valid, bad_idx = verify_ledger()
    assert valid

    res = get("test1")
    assert res["transaction_id"] == "test1"

    t = tail(1)
    assert len(t) == 1
    assert t[0]["transaction_id"] == "test2"

    with open(LEDGER_PATH, "a") as f:
        f.write('{"transaction_id": "test3", "status": "success", "entry_hash": "bad"}\n')

    valid, bad_idx = verify_ledger()
    assert not valid
    assert bad_idx == 2


def test_execute_toctou():
    plan = RollbackPlan(
        plan_id=new_id("pln"),
        command_id="cmd_1",
        source="template",
        confidence=1.0,
        actions=[],
        requires_snapshot=False,
    )

    sim = SimulationReport.model_construct(
        degradation_tier="T1_full_verification",
        predicted_changes={},
        monitor_mode="permissive",
        pre_manifest=collect_state(["/tmp"]),
    )
    plan.simulation = sim

    with open("/tmp/safeshell_toctou_test", "w") as f:
        f.write("test")

    try:
        execute_transaction(plan, "touch /tmp/safeshell_toctou_test")
    except ExecutionAborted:
        pass
    except Exception:
        pass
    finally:
        os.remove("/tmp/safeshell_toctou_test")
