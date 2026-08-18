//! SafeShell core binary — Rust execution engine.
//!
//! Reads a single JSON-lines request from stdin, dispatches the operation,
//! and writes a single JSON-lines response to stdout. All errors are
//! returned as structured JSON rather than panics.

mod ipc;
mod ops;

// Stub modules for future phases
// mod sandbox;   // Phase 7
// mod snapshot;  // Phase 6
// mod state;     // Phase 6
// mod monitor;   // Phase 7
// mod journal;   // Phase 9

use std::io::{self, BufRead, Write};

use tracing_subscriber::EnvFilter;

use crate::ipc::{CoreRequest, CoreResponse};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("warn".parse().unwrap()),
        )
        .init();

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let line = match stdin.lock().lines().next() {
        Some(Ok(l)) => l,
        Some(Err(e)) => {
            let resp = CoreResponse::err(format!("stdin read error: {}", e));
            let _ = serde_json::to_writer(&mut stdout, &resp);
            let _ = writeln!(stdout);
            return;
        }
        None => {
            let resp = CoreResponse::err("no input received");
            let _ = serde_json::to_writer(&mut stdout, &resp);
            let _ = writeln!(stdout);
            return;
        }
    };

    let request: CoreRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = CoreResponse::err(format!("invalid JSON: {}", e));
            let _ = serde_json::to_writer(&mut stdout, &resp);
            let _ = writeln!(stdout);
            return;
        }
    };

    let response = ops::dispatch(&request.op, &request.params);
    let _ = serde_json::to_writer(&mut stdout, &response);
    let _ = writeln!(stdout);
}
