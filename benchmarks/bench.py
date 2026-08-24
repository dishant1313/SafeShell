"""Benchmark suite for SafeShell (Phase 10)"""

import os
import sys
import time
import json
import statistics
from rich.console import Console
from rich.table import Table
import subprocess


def run_benchmarks():
    console = Console()
    
    with open("data/benchmark_commands.json", "r") as f:
        commands = json.load(f)
        
    commands = (commands * 10)[:100]
    
    latencies = []
    successes = 0
    failures = 0
    
    console.print(f"Running benchmarks on {len(commands)} commands...")
    
    for cmd in commands:
        t0 = time.time()
        res = subprocess.run(
            [sys.executable, "-m", "safeshell", "run", cmd, "--dry-run", "--json", "--yes"],
            capture_output=True,
            text=True
        )
        t1 = time.time()
        
        if res.returncode in (0, 2):
            successes += 1
            latencies.append(t1 - t0)
        else:
            failures += 1
            
    avg_latency = statistics.mean(latencies) if latencies else 0
    p95_latency = statistics.quantiles(latencies, n=100)[94] if len(latencies) > 1 else avg_latency
    p99_latency = statistics.quantiles(latencies, n=100)[98] if len(latencies) > 1 else avg_latency
    
    table = Table(title="SafeShell End-to-End Latency Benchmark")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    
    table.add_row("Total Commands", str(len(commands)))
    table.add_row("Successes", str(successes))
    table.add_row("Failures", str(failures))
    table.add_row("Average Latency (s)", f"{avg_latency:.4f}")
    table.add_row("P95 Latency (s)", f"{p95_latency:.4f}")
    table.add_row("P99 Latency (s)", f"{p99_latency:.4f}")
    
    console.print(table)
    
    with open("docs/BENCHMARKS.md", "w") as f:
        f.write("# SafeShell Benchmark Results\n\n")
        f.write(f"- **Total Commands Processed**: {len(commands)}\n")
        f.write(f"- **Successes**: {successes}\n")
        f.write(f"- **Failures**: {failures}\n")
        f.write(f"- **Average Latency**: {avg_latency:.4f}s\n")
        f.write(f"- **P95 Latency**: {p95_latency:.4f}s\n")
        f.write(f"- **P99 Latency**: {p99_latency:.4f}s\n\n")
        f.write("## Target Latency Bands\n")
        f.write("- **T1 (Deterministic Templates)**: < 100ms\n")
        f.write("- **T2 (RAG Retrieval)**: < 500ms\n")
        f.write("- **T3 (LLM Fallback)**: < 5s\n")
        
    return 0


if __name__ == "__main__":
    sys.exit(run_benchmarks())
