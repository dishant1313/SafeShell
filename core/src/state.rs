use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;
use serde::{Deserialize, Serialize};
use tracing::warn;
use crate::ipc::CollectStateParams;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub exists: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StateManifest {
    pub manifest_id: String,
    pub collected_at: String, // RFC3339 UTC
    pub files: Vec<FileEntry>,
    pub services: HashMap<String, String>,
    pub truncated: bool,
}

fn hash_file(path: &str) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn get_service_state(service: &str) -> String {
    let output = Command::new("systemctl")
        .args(["is-active", service])
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                "active".to_string()
            } else if out.status.code() == Some(3) {
                "inactive".to_string()
            } else {
                "unknown".to_string()
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

pub fn collect_state(params: &CollectStateParams) -> StateManifest {
    let mut file_entries = Vec::new();
    let mut truncated = false;
    let mut count = 0;
    let max_files = params.max_files.unwrap_or(5000);

    let mut paths_sorted = params.paths.clone();
    paths_sorted.sort();

    for p in paths_sorted {
        if !fs::metadata(&p).is_ok() && fs::symlink_metadata(&p).is_err() {
            file_entries.push(FileEntry {
                path: p.clone(),
                sha256: "".to_string(),
                mode: 0,
                uid: 0,
                gid: 0,
                size: 0,
                exists: false,
            });
            continue;
        }

        let walker = WalkDir::new(&p).follow_links(false).sort_by_file_name();
        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            if count >= max_files {
                truncated = true;
                break;
            }

            let path_str = entry.path().to_string_lossy().to_string();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to stat {}: {}", path_str, e);
                    continue;
                }
            };

            if metadata.is_file() {
                let sha256 = hash_file(&path_str).unwrap_or_else(|_| "".to_string());
                file_entries.push(FileEntry {
                    path: path_str,
                    sha256,
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    size: metadata.size(),
                    exists: true,
                });
                count += 1;
            } else if metadata.is_symlink() {
                file_entries.push(FileEntry {
                    path: path_str,
                    sha256: "symlink".to_string(),
                    mode: metadata.mode(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    size: metadata.size(),
                    exists: true,
                });
                count += 1;
            }
        }
        if truncated {
            break;
        }
    }

    let mut services = HashMap::new();
    if let Some(srvs) = &params.services {
        for srv in srvs {
            services.insert(srv.clone(), get_service_state(srv));
        }
    }

    // Sort to ensure stable serialization order
    file_entries.sort_by(|a, b| a.path.cmp(&b.path));

    // RFC3339 string UTC
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let dt = datetime::from_timestamp(now);

    let hex_rand = format!("{:x}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos());
    let manifest_id = format!("man_{}", hex_rand);

    StateManifest {
        manifest_id,
        collected_at: dt,
        files: file_entries,
        services,
        truncated,
    }
}

mod datetime {
    pub fn from_timestamp(secs: u64) -> String {
        // Simple manual formatting to RFC3339 for UTC
        // Since we cannot use chrono, we'll shell out to date, or format manually
        let output = std::process::Command::new("date")
            .args(["-u", "+%Y-%m-%dT%H:%M:%SZ", "-d", &format!("@{}", secs)])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                return String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
        }
        "1970-01-01T00:00:00Z".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::env;

    #[test]
    fn test_collect_state() {
        let dir = env::temp_dir().join("ss_test_collect");
        fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("f1.txt");
        fs::write(&f1, b"hello").unwrap();
        let sym = dir.join("sym.txt");
        symlink(&f1, &sym).unwrap();

        let params = CollectStateParams {
            paths: vec![dir.to_string_lossy().to_string()],
            services: None,
            max_files: Some(10),
        };

        let man = collect_state(&params);
        assert_eq!(man.files.len(), 2);
        
        let hello_sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let mut f1_found = false;
        let mut sym_found = false;
        for f in man.files {
            if f.path.ends_with("f1.txt") {
                assert_eq!(f.sha256, hello_sha);
                f1_found = true;
            } else if f.path.ends_with("sym.txt") {
                assert_eq!(f.sha256, "symlink");
                sym_found = true;
            }
        }
        assert!(f1_found);
        assert!(sym_found);
        
        fs::remove_dir_all(dir).unwrap();
    }
}
