use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
#[cfg(feature = "ebpf")]
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorPolicy {
    pub allows_network: bool,
    pub allowed_write_roots: Vec<String>,
    pub kill_on_violation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub ts_ms: u64,
    pub pid: u32,
    pub kind: String,
    pub detail: String,
}

pub struct MonitorHandle {
    pub mode: String,
    stop_flag: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<MonitorEvent>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MonitorHandle {
    pub fn stop(mut self) -> Vec<MonitorEvent> {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let evs = self.events.lock().unwrap();
        evs.clone()
    }
}

pub fn start_monitor(root_pid: u32, policy: MonitorPolicy) -> MonitorHandle {
    #[cfg(feature = "ebpf")]
    {
        // Stretch goal: ebpf implementation could be loaded here.
        // For now, if loading fails, we fallback to polling.
        warn!("eBPF unavailable; fallback polling monitor");
    }

    // Default: polling mode
    let stop_flag = Arc::new(AtomicBool::new(false));
    let events = Arc::new(Mutex::new(Vec::new()));

    let stop_clone = Arc::clone(&stop_flag);
    let events_clone = Arc::clone(&events);
    let policy_clone = policy.clone();

    let thread = thread::spawn(move || {
        let mut seen_pids = HashSet::new();
        seen_pids.insert(root_pid);

        while !stop_clone.load(Ordering::SeqCst) {
            let mut ppid_map: HashMap<u32, u32> = HashMap::new();
            let mut comm_map: HashMap<u32, String> = HashMap::new();

            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(pid) = name.parse::<u32>() {
                        let stat_path = format!("/proc/{}/stat", pid);
                        if let Ok(stat_data) = fs::read_to_string(&stat_path) {
                            // stat format: pid (comm) state ppid ...
                            let parts: Vec<&str> = stat_data.split(' ').collect();
                            if parts.len() > 3 {
                                if let Ok(ppid) = parts[3].parse::<u32>() {
                                    ppid_map.insert(pid, ppid);
                                }
                                let comm = parts[1].trim_matches(|c| c == '(' || c == ')').to_string();
                                comm_map.insert(pid, comm);
                            }
                        }
                    }
                }
            }

            // Find all descendants of root_pid
            let mut descendants = HashSet::new();
            let mut queue = vec![root_pid];
            while let Some(current) = queue.pop() {
                for (&pid, &ppid) in &ppid_map {
                    if ppid == current && !descendants.contains(&pid) {
                        descendants.insert(pid);
                        queue.push(pid);
                    }
                }
            }

            let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

            for pid in descendants {
                if !seen_pids.contains(&pid) {
                    seen_pids.insert(pid);
                    let comm = comm_map.get(&pid).cloned().unwrap_or_else(|| "unknown".to_string());
                    
                    let mut evs = events_clone.lock().unwrap();
                    evs.push(MonitorEvent {
                        ts_ms,
                        pid,
                        kind: "exec".to_string(),
                        detail: comm.clone(),
                    });

                    // Kill if unexpected. For now, we consider anything outside common shell commands as potentially unexpected if kill_on_violation is true
                    if policy_clone.kill_on_violation {
                        let allowed = ["sh", "bash", "sleep", "echo", "cat", "wget", "curl", "ls", "rm", "mv", "cp", "readlink", "true"];
                        if !allowed.contains(&comm.as_str()) {
                            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(50));
        }
    });

    MonitorHandle {
        mode: "polling".to_string(),
        stop_flag,
        events,
        thread: Some(thread),
    }
}
