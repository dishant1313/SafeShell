use crate::ipc::CollectStateParams;
use crate::monitor::{start_monitor, MonitorPolicy};
use crate::state::{collect_state, FileEntry};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{chdir, chroot, fork, pipe, read, write, ForkResult, Uid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecParams {
    pub argv: Vec<String>,
    pub scope_paths: Vec<String>,
    pub timeout_s: Option<u64>,
    pub allow_network: Option<bool>,
    pub monitor_policy: Option<MonitorPolicy>,
    pub upper_base: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCfg {
    pub scope_paths: Vec<String>,
    pub timeout_s_per_step: Option<u64>,
    pub allow_network: Option<bool>,
    pub monitor_policy: Option<MonitorPolicy>,
    pub upper_base: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub argv: Vec<String>,
    pub name: String,
}

pub fn run_session(cfg: &SessionCfg, steps: &[Step]) -> Result<Value, String> {
    if !Uid::current().is_root() {
        return Err("requires CAP_SYS_ADMIN (run with sudo)".to_string());
    }

    let timeout_s = cfg.timeout_s_per_step.unwrap_or(10);
    let allow_network = cfg.allow_network.unwrap_or(false);
    let upper_base = cfg.upper_base.clone().unwrap_or_else(|| ".safeshell/sandbox".to_string());
    
    let uniq = std::process::id().to_string();
    let base_path = PathBuf::from(&upper_base).join(&uniq);
    let upper_dir = base_path.join("upper");
    let work_dir = base_path.join("work");
    let merged_dir = base_path.join("merged");

    fs::create_dir_all(&upper_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&work_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&merged_dir).map_err(|e| e.to_string())?;

    let data = format!("lowerdir=/,upperdir={},workdir={}", upper_dir.display(), work_dir.display());
    if let Err(e) = mount(
        Some("overlay"),
        &merged_dir,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    ) {
        return Err(format!("mount overlay failed: {}", e));
    }

    let scope_paths_merged: Vec<String> = cfg.scope_paths.iter().map(|p| {
        let rel = p.trim_start_matches('/');
        merged_dir.join(rel).to_string_lossy().to_string()
    }).collect();

    let pre_manifest = collect_state(&CollectStateParams { paths: scope_paths_merged.clone(), max_files: None, services: None });

    let mut step_results = Vec::new();
    let mut intermediate_manifest = None;
    let mut all_events = Vec::new();
    let mut monitor_mode = "enforcing".to_string();

    for (i, step) in steps.iter().enumerate() {
        let (r_ready, w_ready) = pipe().map_err(|e| e.to_string())?;
        let (r_go, w_go) = pipe().map_err(|e| e.to_string())?;
        let (r_out, w_out) = pipe().map_err(|e| e.to_string())?;
        let (r_err, w_err) = pipe().map_err(|e| e.to_string())?;

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let mut flags = CloneFlags::CLONE_NEWNS;
                if !allow_network {
                    flags |= CloneFlags::CLONE_NEWNET;
                }
                if let Err(e) = unshare(flags) { let msg = format!("unshare failed: {}\n", e); let _ = write(&w_err, msg.as_bytes()); std::process::exit(1); }
                if let Err(e) = chroot(&merged_dir) { let msg = format!("chroot failed: {}\n", e); let _ = write(&w_err, msg.as_bytes()); std::process::exit(1); }
                if let Err(e) = chdir("/") { let msg = format!("chdir / failed: {}\n", e); let _ = write(&w_err, msg.as_bytes()); std::process::exit(1); }

                let _ = mount(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), Some(""));

                let _ = write(&w_ready, b"r");

                let mut buf = [0u8; 1];
                let _ = read(r_go.as_raw_fd(), &mut buf);

                let _ = nix::unistd::dup2(w_out.as_raw_fd(), 1);
                let _ = nix::unistd::dup2(w_err.as_raw_fd(), 2);
                let _ = nix::unistd::close(w_out.as_raw_fd());
                let _ = nix::unistd::close(r_out.as_raw_fd());
                let _ = nix::unistd::close(w_err.as_raw_fd());
                let _ = nix::unistd::close(r_err.as_raw_fd());

                std::env::set_var("PATH", "/usr/bin:/bin");
                std::env::set_var("HOME", "/tmp");
                std::env::set_var("TERM", "dumb");

                let c_args: Vec<CString> = step.argv.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
                let err = nix::unistd::execvp(&c_args[0], &c_args).unwrap_err();
                let msg = format!("execvp failed: {}\n", err);
                let _ = write(&w_err, msg.as_bytes());
                std::process::exit(1);
            }
            Ok(ForkResult::Parent { child }) => {
                nix::unistd::close(w_ready.as_raw_fd()).ok();
                nix::unistd::close(r_go.as_raw_fd()).ok();
                nix::unistd::close(w_out.as_raw_fd()).ok();
                nix::unistd::close(w_err.as_raw_fd()).ok();

                let mut buf = [0u8; 1];
                if read(r_ready.as_raw_fd(), &mut buf).is_err() {
                    let _ = umount2(&merged_dir, MntFlags::MNT_DETACH);
                    return Err("Failed to sync with child".to_string());
                }

                let policy = cfg.monitor_policy.clone().unwrap_or(MonitorPolicy {
                    allows_network: allow_network,
                    allowed_write_roots: cfg.scope_paths.clone(),
                    kill_on_violation: true,
                });
                let monitor = start_monitor(child.as_raw() as u32, policy);

                let _ = write(&w_go, b"g");
                
                let start = Instant::now();
                let mut exit_code = -1;

                loop {
                    match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::Exited(_, code)) => {
                            exit_code = code;
                            break;
                        }
                        Ok(WaitStatus::Signaled(_, sig, _)) => {
                            exit_code = 128 + sig as i32;
                            break;
                        }
                        Ok(WaitStatus::StillAlive) => {
                            if start.elapsed().as_secs() >= timeout_s {
                                let _ = kill(child, Signal::SIGTERM);
                                thread::sleep(Duration::from_secs(2));
                                let _ = kill(child, Signal::SIGKILL);
                                let _ = waitpid(child, None);
                                exit_code = 124;
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        _ => break,
                    }
                }
                let duration_ms = start.elapsed().as_millis() as u64;

                monitor_mode = monitor.mode.clone();
                let events = monitor.stop();
                all_events.extend(events);

                let mut stdout_tail = String::new();
                let mut stderr_tail = String::new();
                let mut out_buf = [0u8; 4096];
                if let Ok(n) = read(r_out.as_raw_fd(), &mut out_buf) {
                    stdout_tail = String::from_utf8_lossy(&out_buf[..n]).into_owned();
                }
                if let Ok(n) = read(r_err.as_raw_fd(), &mut out_buf) {
                    stderr_tail = String::from_utf8_lossy(&out_buf[..n]).into_owned();
                }

                step_results.push(serde_json::json!({
                    "name": step.name,
                    "exit_code": exit_code,
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                    "duration_ms": duration_ms,
                }));

                if i == 0 {
                    intermediate_manifest = Some(collect_state(&CollectStateParams { paths: scope_paths_merged.clone(), max_files: None, services: None }));
                }
            }
            Err(e) => {
                let _ = umount2(&merged_dir, MntFlags::MNT_DETACH);
                return Err(format!("Fork failed: {}", e));
            }
        }
    }

    let post_manifest = collect_state(&CollectStateParams { paths: scope_paths_merged.clone(), max_files: None, services: None });

    let int_manifest = intermediate_manifest.unwrap_or_else(|| pre_manifest.clone());

    let mut predicted_changes = serde_json::json!({
        "files_deleted": 0,
        "files_modified": 0,
        "permissions_changed": 0,
        "processes_spawned": all_events.len(),
        "network_attempts": 0,
    });

    let pre_map: HashMap<String, &FileEntry> = pre_manifest.files.iter().map(|f| (f.path.clone(), f)).collect();
    let int_map: HashMap<String, &FileEntry> = int_manifest.files.iter().map(|f| (f.path.clone(), f)).collect();

    let mut files_deleted = 0;
    let mut files_modified = 0;
    let mut permissions_changed = 0;

    for (path, pre_entry) in &pre_map {
        if let Some(int_entry) = int_map.get(path) {
            if !pre_entry.exists && int_entry.exists {
                files_modified += 1;
            } else if pre_entry.exists && !int_entry.exists {
                files_deleted += 1;
            } else if pre_entry.exists && int_entry.exists {
                if pre_entry.sha256 != int_entry.sha256 {
                    files_modified += 1;
                } else if pre_entry.mode != int_entry.mode {
                    permissions_changed += 1;
                }
            }
        } else if pre_entry.exists {
            files_deleted += 1;
        }
    }
    
    for (path, int_entry) in &int_map {
        if !pre_map.contains_key(path) && int_entry.exists {
            files_modified += 1;
        }
    }

    predicted_changes["files_deleted"] = serde_json::json!(files_deleted);
    predicted_changes["files_modified"] = serde_json::json!(files_modified);
    predicted_changes["permissions_changed"] = serde_json::json!(permissions_changed);

    let _ = umount2(&merged_dir, MntFlags::MNT_DETACH);
    let _ = fs::remove_dir_all(&upper_dir);
    let _ = fs::remove_dir_all(&work_dir);
    let _ = fs::remove_dir_all(&merged_dir);
    let _ = fs::remove_dir_all(&base_path);

    Ok(serde_json::json!({
        "steps": step_results,
        "monitor_mode": monitor_mode,
        "predicted_changes": predicted_changes,
        "events": all_events,
        "pre_manifest": serde_json::to_value(&pre_manifest).unwrap(),
        "post_manifest": serde_json::to_value(&post_manifest).unwrap(),
    }))
}

pub fn sandbox_exec(params: &SandboxExecParams) -> Result<Value, String> {
    let cfg = SessionCfg {
        scope_paths: params.scope_paths.clone(),
        timeout_s_per_step: params.timeout_s,
        allow_network: params.allow_network,
        monitor_policy: params.monitor_policy.clone(),
        upper_base: params.upper_base.clone(),
    };
    
    let steps = vec![
        Step {
            argv: params.argv.clone(),
            name: "command".to_string(),
        }
    ];

    let result = run_session(&cfg, &steps)?;
    
    let mut exit_code = -1;
    let mut stdout_tail = String::new();
    let mut stderr_tail = String::new();
    let mut duration_ms = 0;
    
    if let Some(steps_arr) = result.get("steps").and_then(|s| s.as_array()) {
        if let Some(first) = steps_arr.first() {
            exit_code = first.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
            stdout_tail = first.get("stdout_tail").and_then(|v| v.as_str()).unwrap_or("").to_string();
            stderr_tail = first.get("stderr_tail").and_then(|v| v.as_str()).unwrap_or("").to_string();
            duration_ms = first.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
        }
    }

    Ok(serde_json::json!({
        "exit_code": exit_code,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "duration_ms": duration_ms,
        "monitor_mode": result.get("monitor_mode").cloned().unwrap_or(Value::Null),
        "predicted_changes": result.get("predicted_changes").cloned().unwrap_or(Value::Null),
        "events": result.get("events").cloned().unwrap_or(Value::Null),
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteParams {
    pub argv: Vec<String>,
    pub timeout_s: Option<u64>,
}

pub fn execute(params: &ExecuteParams) -> Result<Value, String> {
    let (r_out, w_out) = nix::unistd::pipe().map_err(|e| e.to_string())?;
    let (r_err, w_err) = nix::unistd::pipe().map_err(|e| e.to_string())?;

    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Child) => {
            nix::unistd::close(r_out.as_raw_fd()).ok();
            nix::unistd::close(r_err.as_raw_fd()).ok();

            nix::unistd::dup2(w_out.as_raw_fd(), 1).ok();
            nix::unistd::dup2(w_err.as_raw_fd(), 2).ok();
            
            let c_args: Vec<std::ffi::CString> = params.argv.iter().map(|a| std::ffi::CString::new(a.as_str()).unwrap()).collect();
            let err = nix::unistd::execvp(&c_args[0], &c_args).unwrap_err();
            let msg = format!("execvp failed: {}\n", err);
            let _ = nix::unistd::write(&w_err, msg.as_bytes());
            std::process::exit(1);
        }
        Ok(ForkResult::Parent { child }) => {
            nix::unistd::close(w_out.as_raw_fd()).ok();
            nix::unistd::close(w_err.as_raw_fd()).ok();

            let policy = crate::monitor::MonitorPolicy {
                allows_network: true,
                allowed_write_roots: vec!["/".to_string()], // allow everything basically?
                kill_on_violation: false, // Just monitor
            };
            let monitor = crate::monitor::start_monitor(child.as_raw() as u32, policy);
            
            let start = std::time::Instant::now();
            let mut exit_code = -1;
            let timeout_s = params.timeout_s.unwrap_or(30);

            loop {
                match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                        exit_code = code;
                        break;
                    }
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                        exit_code = 128 + sig as i32;
                        break;
                    }
                    Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                        if start.elapsed().as_secs() >= timeout_s {
                            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGTERM);
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                            let _ = nix::sys::wait::waitpid(child, None);
                            exit_code = 124;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    _ => break,
                }
            }
            let duration_ms = start.elapsed().as_millis() as u64;
            
            let events = monitor.stop();
            
            let mut stdout_tail = String::new();
            let mut stderr_tail = String::new();
            let mut out_buf = [0u8; 4096];
            if let Ok(n) = nix::unistd::read(r_out.as_raw_fd(), &mut out_buf) {
                stdout_tail = String::from_utf8_lossy(&out_buf[..n]).into_owned();
            }
            if let Ok(n) = nix::unistd::read(r_err.as_raw_fd(), &mut out_buf) {
                stderr_tail = String::from_utf8_lossy(&out_buf[..n]).into_owned();
            }

            Ok(serde_json::json!({
                "exit_code": exit_code,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "duration_ms": duration_ms,
                "events": events,
            }))
        }
        Err(e) => Err(format!("Fork failed: {}", e)),
    }
}
