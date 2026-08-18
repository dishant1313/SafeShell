//! Operation dispatch for safeshell-core.
//!
//! Maps operation strings to handler functions. Currently all operations
//! return NotImplemented errors; real implementations arrive in Phases 6–8.

use serde_json::Value;

use crate::ipc::CoreResponse;

/// Dispatch an operation by name.
///
/// # Operations (implementation phase)
/// - `collect_state` — Phase 6: Trusted state collector
/// - `snapshot` — Phase 6: Filesystem snapshots
/// - `restore` — Phase 6: Snapshot restoration
/// - `sandbox_exec` — Phase 7: Namespace + OverlayFS sandbox
/// - `simulate` — Phase 8: Full simulation with rollback verification
pub fn dispatch(op: &str, _params: &Value) -> CoreResponse {
    CoreResponse::err(format!("NotImplemented: {}", op))
}
