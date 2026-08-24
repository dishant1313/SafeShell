"""Rich Typer CLI app (Phase 10)"""

import json
import os
os.environ["RUN_LLM"] = "1"
import subprocess
import sys
from datetime import datetime, timezone

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from safeshell import __version__
from safeshell.brs import blast_radius
from safeshell.classifier import classify
from safeshell.explain import explain
from safeshell.ledger import get as get_ledger
from safeshell.ledger import tail as tail_ledger
from safeshell.ledger import verify_ledger
from safeshell.parser import parse_command
from safeshell.planner_cascade import NoVerifiedPlan, make_plan
from safeshell.policy import evaluate
from safeshell.replay import replay, replay_since
from safeshell.replay import whatif as run_whatif
from safeshell.schemas import RollbackPlan

app = typer.Typer(
    help="SafeShell: Verified transactional command execution framework.", no_args_is_help=True
)
console = Console()


@app.command()
def version():
    """Print the version and exit."""
    console.print(f"SafeShell version: {__version__}")


@app.command()
def analyze(command: str = typer.Argument(..., help="The command string to analyze")):
    parsed = parse_command(command)
    risk = classify(parsed, command)
    brs = blast_radius(parsed, risk)
    console.print(parsed.model_dump_json(indent=2))
    console.print(
        f"\\nRisk Level: {risk.level.value} | Score: {risk.score:.4f} | Signals: {risk.signals}"
    )
    console.print(f"\\nBlast Radius: {brs.score} | Signals: {brs.top_signals}")


@app.command()
def policy_check(
    command: str = typer.Argument(...), guarantee: str = typer.Option("T1", "--guarantee", "-g")
):
    parsed = parse_command(command)
    risk = classify(parsed, command)
    brs = blast_radius(parsed, risk)
    decision = evaluate(tier=risk.level.value, brs=brs.score, guarantee=guarantee)
    console.print(decision.model_dump_json(indent=2))


@app.command()
def plan(
    command: str = typer.Argument(...),
    file: str = typer.Option(None, "--file", "-f"),
    n: int = typer.Option(None, "--n", "-n"),
):
    try:
        res = make_plan(command, file, n)
        if res.path == "denied":
            console.print(f"[red]Plan Denied[/red]: {res.denied_reason}")
            raise typer.Exit(code=2)

        selected = res.candidates[res.selected_index] if res.candidates else None
        out = {
            "path": res.path,
            "selected_index": res.selected_index,
            "candidates_tried": selected.candidates_tried
            if selected and hasattr(selected, "candidates_tried")
            else len(res.candidates),
            "plan": selected.model_dump() if selected else None,
        }
        print(json.dumps(out))
    except NoVerifiedPlan as e:
        console.print(f"[red]Error[/red]: {e}")
        raise typer.Exit(code=2)


@app.command()
def simulate():
    """Simulate a command (Not implemented directly here, use plan or run)."""
    console.print("Simulation is run during `plan` or `run` automatically.")


@app.command("run")
def run_cmd(
    command: str = typer.Argument(...),
    file: str = typer.Option(None, "--file", "-f"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve"),
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable color output"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Stop before execution"),
    explain_flag: bool = typer.Option(False, "--explain", help="Include explanation"),
    accept_irreversible: bool = typer.Option(
        False, "--accept-irreversible", help="Accept T3 actions"
    ),
):
    """Run a transaction with SafeShell."""
    if no_color:
        global console
        console = Console(color_system=None)

    try:
        res = make_plan(command, file=file, accept_irreversible=accept_irreversible)
    except NoVerifiedPlan as e:
        if json_out:
            print(json.dumps({"error": str(e), "status": "blocked"}))
        else:
            console.print(f"[red]Transaction denied[/red]: {e}")
        raise typer.Exit(code=2)

    if res.path == "denied":
        if json_out:
            print(json.dumps({"error": res.denied_reason, "status": "blocked"}))
        else:
            console.print(f"[red]Transaction denied[/red]: {res.denied_reason}")
        raise typer.Exit(code=2)

    plan_obj = res.candidates[res.selected_index]
    analysis = res.analysis
    sim = plan_obj.simulation

    if json_out:
        out = {
            "cmd": command,
            "brs": analysis.blast_radius.score if analysis else 0,
            "top_signals": analysis.blast_radius.top_signals if analysis else [],
            "tier": sim.degradation_tier.value if sim else "unknown",
            "guarantee": sim.degradation_tier.value if sim else "unknown",
            "simulation": sim.model_dump() if sim else None,
            "explanation": explain(analysis, plan_obj) if analysis else "",
        }
        print(json.dumps(out))
        # Wait, for JSON, do we execute if --yes is given?
        # The prompt says: "if policy auto_approve (and --yes or non-tty) => mode policy_auto; else TUI"
        if not yes and sys.stdin.isatty():
            raise typer.Exit(code=0)  # Dry run essentially if no auto approve in JSON

    is_tty = sys.stdin.isatty()
    decision = evaluate(
        tier=analysis.risk.level.value if analysis else "high",
        brs=analysis.blast_radius.score if analysis else 0,
        guarantee=sim.degradation_tier.value.split("_")[0] if sim else "T1",
    )

    from safeshell.anomaly import score_transaction

    is_anomaly = score_transaction(
        {
            "command": command,
            "brs": analysis.blast_radius.score if analysis else 0,
            "timestamp": datetime.now(timezone.utc).timestamp(),
        }
    )
    if is_anomaly:
        decision.action = "require_human"

    if (yes or not is_tty) and decision.action == "auto_approve":
        pass  # Auto approved
    elif not json_out:
        # Show TUI
        header_text = (
            "[bold cyan]Not a safer folder. A safer shell — every system effect, undoable.[/bold cyan]\n"
            "[dim]AI proposes. Simulation decides. SafeShell remembers — and learns.[/dim]\n\n"
        )
        brs_score = analysis.blast_radius.score if analysis else 0
        signals = ", ".join((analysis.blast_radius.top_signals if analysis else [])[:3])
        tier = sim.degradation_tier.value if sim else "Unknown"

        info = (
            header_text
            + f"[bold yellow]Risk Tier:[/bold yellow] {analysis.risk.level.value if analysis else 'Unknown'} | [bold yellow]BRS:[/bold yellow] {brs_score} ({signals})\\n"
        )

        if sim:
            info += f"[bold blue]Impact:[/bold blue] {sim.predicted_changes.files_modified} modified, {sim.predicted_changes.files_deleted} deleted\\n"
            info += f"[bold green]Simulation:[/bold green] Verdict: {'Verified' if sim.rollback_verified else 'Failed'} in {sim.duration_ms}ms\\n"

        info += f"[bold magenta]Guarantee:[/bold magenta] {tier}\\n"

        if analysis:
            info += f"\\n[italic]{explain(analysis, plan_obj)}[/italic]\\n"

        if len(res.candidates) > 1:
            info += f"\\n[dim]Plan selected by simulation: candidate {res.selected_index + 1} of {len(res.candidates)}[/dim]\\n"

        table = Table(title="Rollback Plan")
        table.add_column("Order")
        table.add_column("Type")
        table.add_column("Target")

        for a in plan_obj.actions:
            table.add_row(str(a.order), a.type.value, a.target)

        panel = Panel(
            info + "\\n" + table.__rich_console__(console, console.options)[0].text,
            title=f"SafeShell Proposal: {command}",
        )
        console.print(panel)

        while True:
            choice = Prompt.ask(
                "[A]pprove [R]eject [E]dit", choices=["a", "r", "e", "A", "R", "E"], default="R"
            )
            choice = choice.lower()
            if choice == "r":
                console.print("[red]Rejected.[/red]")
                raise typer.Exit(code=2)
            elif choice == "a":
                break
            elif choice == "e":
                # Edit plan
                import tempfile

                with tempfile.NamedTemporaryFile(suffix=".json", mode="w+", delete=False) as tf:
                    tf.write(plan_obj.model_dump_json(indent=2))
                    name = tf.name
                editor = os.environ.get("EDITOR", "nano")
                subprocess.run([editor, name])
                try:
                    with open(name, "r") as f:
                        data = json.load(f)
                    plan_obj = RollbackPlan.model_validate(data)
                    # We should technically re-validate and re-simulate here.
                    from safeshell.validator import sign_plan, validate

                    plan_obj = validate(plan_obj, analysis.parsed)
                    from safeshell.simulation import simulate

                    plan_obj.simulation = simulate(analysis.parsed, plan_obj)
                    sign_plan(plan_obj)
                    console.print("[green]Plan edited and re-simulated successfully.[/green]")
                    break
                except Exception as e:
                    console.print(f"[red]Error parsing or validating edited plan:[/red] {e}")
                    raise typer.Exit(code=2)

    if dry_run:
        console.print("[yellow]Dry run finished.[/yellow]")
        raise typer.Exit(code=0)

    try:
        from safeshell.executor import execute_transaction
        from safeshell.learn import maybe_writeback
        from safeshell.ledger import append as append_ledger

        execution_info = {
            "status": "committed",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "divergence_detected": False,
        }

        try:
            result = execute_transaction(plan_obj, command)
            execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
            if not json_out:
                console.print("[green]Transaction succeeded.[/green]")
        except Exception as e:
            from safeshell.executor import ExecutionAborted, ExecutionFailed

            if isinstance(e, ExecutionAborted):
                execution_info["status"] = "blocked"
                execution_info["divergence_detected"] = True
                execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
                if not json_out:
                    console.print(f"[red]Transaction aborted:[/red] {e}")
                exit_code = 1
            elif isinstance(e, ExecutionFailed):
                execution_info["status"] = "rolled_back"
                execution_info["completed_at"] = datetime.now(timezone.utc).isoformat()
                if not json_out:
                    console.print(f"[red]Transaction failed and rolled back:[/red] {e}")
                exit_code = 3
            else:
                raise

        record_dict = {
            "transaction_id": plan_obj.plan_id,
            "command_id": analysis.command_id if analysis else plan_obj.command_id,
            "plan_id": plan_obj.plan_id,
            "simulation_id": plan_obj.simulation.simulation_id if plan_obj.simulation else "none",
            "approval": {
                "required": True,
                "mode": "human" if not yes and is_tty else "policy_auto",
                "approved_by": "user",
                "approved_at": datetime.now(timezone.utc).isoformat(),
            },
            "execution": execution_info,
            "learning": {"template_written_back": False, "template_id": None},
            "brs": analysis.blast_radius.score
            if analysis and hasattr(analysis, "blast_radius")
            else 0,
            "brs_version": analysis.blast_radius.brs_version
            if analysis and hasattr(analysis, "blast_radius")
            else "v1",
            "plan": plan_obj.model_dump(),
            "pre_hash": plan_obj.simulation.pre_manifest.manifest_id
            if plan_obj.simulation
            and hasattr(plan_obj.simulation, "pre_manifest")
            and plan_obj.simulation.pre_manifest
            else "unknown",
            "prev_hash": "",
            "entry_hash": "",
        }

        if analysis and plan_obj.simulation:
            record_dict = maybe_writeback(record_dict, plan_obj, analysis, plan_obj.simulation)

        append_ledger(record_dict)

        if execution_info["status"] == "rolled_back":
            raise typer.Exit(code=3)
        elif execution_info["status"] == "blocked":
            raise typer.Exit(code=2)

        raise typer.Exit(code=0)

    except Exception as e:
        if not json_out:
            console.print(f"[red]Error during execution:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def undo(txn_id: str = typer.Argument(...)):
    """Undo a transaction."""
    from safeshell.recovery import rollback

    record = get_ledger(txn_id)
    if not record:
        console.print("[red]Transaction not found[/red]")
        raise typer.Exit(1)

    plan_dict = record.get("plan")
    if not plan_dict:
        console.print("[red]Plan not available in ledger[/red]")
        raise typer.Exit(1)

    plan = RollbackPlan.model_validate(plan_dict)

    try:
        from safeshell.parser import parse_command
        from safeshell.state import collect_state

        parsed = parse_command(record["command"])
        manifest = collect_state(parsed.resolved_paths)
        rollback(plan, manifest)
        console.print("[green]Undo completed.[/green]")
    except Exception as e:
        console.print(f"[red]Undo failed:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def recover():
    """Manual L3 recovery console."""
    console.print("Recovery console initialized.")
    raise typer.Exit(code=4)


@app.command()
def status(json_out: bool = typer.Option(False, "--json", help="JSON output")):
    """Show SafeShell status."""
    st = {"healthy": True, "ledger_entries": len(tail_ledger(100))}
    if json_out:
        print(json.dumps(st))
    else:
        console.print(f"Status: {st}")


@app.command()
def ledger(verify: bool = typer.Option(False, "--verify", help="Verify the ledger chain")):
    """View or verify the ledger."""
    if verify:
        is_valid, idx = verify_ledger()
        if is_valid:
            console.print("[green]Ledger verified successfully.[/green]")
        else:
            console.print(f"[red]Ledger verification failed at index {idx}.[/red]")
            raise typer.Exit(1)
    else:
        records = tail_ledger(10)
        for r in records:
            console.print(json.dumps(r))


@app.command("replay")
def run_replay(txn_id: str = typer.Argument(None), since: str = typer.Option(None, "--since")):
    """Replay a transaction to check drift."""
    if since:
        reports = replay_since(since)
        for r in reports:
            console.print(r.model_dump_json(indent=2))
    elif txn_id:
        rep = replay(txn_id)
        if rep:
            console.print(f"Verdict: {rep.verdict.value}")
            console.print(rep.model_dump_json(indent=2))
        else:
            console.print("[red]Replay failed or txn not found.[/red]")


@app.command()
def whatif(command: str = typer.Argument(...)):
    """Analyze what if a command was run."""
    res = run_whatif(command)
    console.print(json.dumps(res, indent=2))


@app.command()
def selftest():
    """Run the SafeShell self-test battery."""
    import subprocess

    cmd = ["python3", "-m", "pytest", "-v", "tests/test_selftest.py"]
    res = subprocess.run(cmd)
    raise typer.Exit(code=res.returncode)
