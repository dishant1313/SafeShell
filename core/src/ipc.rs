//! JSON-lines IPC protocol between Python orchestrator and safeshell-core.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Incoming request from the Python CLI.
#[derive(Debug, Deserialize)]
pub struct CoreRequest {
    pub op: String,
    pub params: Value,
}

/// Outgoing response to the Python CLI.
#[derive(Debug, Serialize)]
pub struct CoreResponse {
    pub ok: bool,
    pub data: Value,
    pub error: Option<String>,
}

impl CoreResponse {
    /// Success response with data.
    #[allow(dead_code)]
    pub fn ok(data: Value) -> Self {
        Self {
            ok: true,
            data,
            error: None,
        }
    }

    /// Error response with message.
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: Value::Object(serde_json::Map::new()),
            error: Some(msg.into()),
        }
    }
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectStateParams {
    pub paths: Vec<String>,
    pub services: Option<Vec<String>>,
    pub max_files: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotParams {
    pub paths: Vec<String>,
    pub snapshot_id: String,
    pub snapshots_dir: String,
    pub services: Option<Vec<String>>,
    pub max_files: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreParams {
    pub snapshot_id: String,
    pub snapshots_dir: String,
}
