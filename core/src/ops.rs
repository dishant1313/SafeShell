//! Operation dispatch for safeshell-core.
//!
//! Maps operation strings to handler functions. Currently all operations

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ipc::CoreResponse;
use crate::ipc::{CollectStateParams, SnapshotParams, RestoreParams};
use crate::state::collect_state;
use crate::snapshot::{snapshot, restore};
use crate::sandbox::{sandbox_exec, run_session, SandboxExecParams, SessionCfg, Step};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateParams {
    pub command_argv: Vec<String>,
    pub rollback_steps: Vec<Vec<String>>,
    pub scope_paths: Vec<String>,
    pub timeout_s: Option<u64>,
    pub allow_network: Option<bool>,
    pub monitor_policy: Option<crate::monitor::MonitorPolicy>,
}

pub fn dispatch(op: &str, params: &Value) -> CoreResponse {
    match op {
        "collect_state" => {
            let p: Result<CollectStateParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => {
                    let manifest = collect_state(&p);
                    CoreResponse::ok(serde_json::to_value(manifest).unwrap())
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }
        "snapshot" => {
            let p: Result<SnapshotParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => {
                    match snapshot(&p) {
                        Ok(data) => CoreResponse::ok(data),
                        Err(e) => CoreResponse::err(e),
                    }
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }
        "restore" => {
            let p: Result<RestoreParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => {
                    match restore(&p) {
                        Ok(data) => CoreResponse::ok(data),
                        Err(e) => {
                            if let Ok(val) = serde_json::from_str::<Value>(&e) {
                                let mut r = CoreResponse::err("Restore mismatch");
                                r.data = val;
                                r
                            } else {
                                CoreResponse::err(e)
                            }
                        }
                    }
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }
        "sandbox_exec" => {
            let p: Result<SandboxExecParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => match sandbox_exec(&p) {
                    Ok(data) => CoreResponse::ok(data),
                    Err(e) => CoreResponse::err(e),
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }
        "simulate" => {
            let p: Result<SimulateParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => {
                    let cfg = SessionCfg {
                        scope_paths: p.scope_paths,
                        timeout_s_per_step: p.timeout_s,
                        allow_network: p.allow_network,
                        monitor_policy: p.monitor_policy,
                        upper_base: None,
                    };
                    let mut steps = vec![
                        Step {
                            argv: p.command_argv,
                            name: "command".to_string(),
                        }
                    ];
                    for (i, rb_argv) in p.rollback_steps.into_iter().enumerate() {
                        steps.push(Step {
                            argv: rb_argv,
                            name: format!("rollback_{}", i),
                        });
                    }
                    match run_session(&cfg, &steps) {
                        Ok(mut data) => {
                            let mut verified = true;
                            if let (Some(pre), Some(post)) = (data.get("pre_manifest"), data.get("post_manifest")) {
                                let pre_files = pre.get("files").and_then(|f| f.as_array());
                                let post_files = post.get("files").and_then(|f| f.as_array());
                                if let (Some(pre_f), Some(post_f)) = (pre_files, post_files) {
                                    let mut pre_map = std::collections::HashMap::new();
                                    for f in pre_f {
                                        pre_map.insert(f.get("path").unwrap().as_str().unwrap(), f);
                                    }
                                    let mut post_map = std::collections::HashMap::new();
                                    for f in post_f {
                                        post_map.insert(f.get("path").unwrap().as_str().unwrap(), f);
                                    }
                                    if pre_map.len() != post_map.len() {
                                        verified = false;
                                    } else {
                                        for (path, pre_entry) in &pre_map {
                                            if let Some(post_entry) = post_map.get(path) {
                                                if pre_entry.get("sha256") != post_entry.get("sha256") ||
                                                   pre_entry.get("mode") != post_entry.get("mode") ||
                                                   pre_entry.get("exists") != post_entry.get("exists") {
                                                    verified = false;
                                                    break;
                                                }
                                            } else {
                                                verified = false;
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    verified = false;
                                }
                            } else {
                                verified = false;
                            }

                            use sha2::{Sha256, Digest};
                            let mut post_hash = String::new();
                            if let Some(post) = data.get("post_manifest") {
                                if let Ok(s) = serde_json::to_string(post) {
                                    let mut hasher = Sha256::new();
                                    hasher.update(s.as_bytes());
                                    post_hash = format!("{:x}", hasher.finalize());
                                }
                            }
                            
                            let mut total_duration = 0;
                            if let Some(steps_arr) = data.get("steps").and_then(|s| s.as_array()) {
                                for step in steps_arr {
                                    if let Some(dur) = step.get("duration_ms").and_then(|v| v.as_u64()) {
                                        total_duration += dur;
                                    }
                                }
                            }
                            
                            if let Some(obj) = data.as_object_mut() {
                                obj.insert("rollback_verified".to_string(), serde_json::json!(verified));
                                obj.insert("post_rollback_state_hash".to_string(), serde_json::json!(post_hash));
                                obj.insert("matches_pre_execution_hash".to_string(), serde_json::json!(verified));
                                obj.insert("duration_ms".to_string(), serde_json::json!(total_duration));
                            }
                            CoreResponse::ok(data)
                        },
                        Err(e) => CoreResponse::err(e),
                    }
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }
        
        "execute" => {
            let p: Result<crate::sandbox::ExecuteParams, _> = serde_json::from_value(params.clone());
            match p {
                Ok(p) => match crate::sandbox::execute(&p) {
                    Ok(data) => CoreResponse::ok(data),
                    Err(e) => CoreResponse::err(e),
                }
                Err(e) => CoreResponse::err(format!("Invalid params: {}", e)),
            }
        }

        _ => CoreResponse::err(format!("Unknown op: {}", op)),
    }
}
