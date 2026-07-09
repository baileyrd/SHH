//! The saved-host list: a small JSON file next to the CLI's own dotfiles
//! (`~/.shh/gui_hosts.json`), so the GUI is just another consumer of the
//! same `~/.shh` home the `shh`/`shhd`/`shh-agent` binaries already use.

use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// Explicit identity file path; `None` uses shh's own default search
    /// (`~/.shh/id_ed25519`, then `~/.ssh/id_ed25519`).
    pub identity: Option<String>,
}

pub struct HostStore {
    path: std::path::PathBuf,
    hosts: Mutex<Vec<Host>>,
}

fn random_id() -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl HostStore {
    pub fn load() -> Self {
        let path = shh::client::default_path("gui_hosts.json");
        let hosts = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        HostStore {
            path,
            hosts: Mutex::new(hosts),
        }
    }

    fn persist(&self, hosts: &[Host]) -> Result<(), String> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(hosts).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, text).map_err(|e| e.to_string())
    }

    pub fn list(&self) -> Vec<Host> {
        self.hosts.lock().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<Host> {
        self.hosts.lock().unwrap().iter().find(|h| h.id == id).cloned()
    }

    pub fn upsert(&self, mut host: Host) -> Result<Host, String> {
        let mut hosts = self.hosts.lock().unwrap();
        if host.id.is_empty() {
            host.id = random_id();
            hosts.push(host.clone());
        } else if let Some(existing) = hosts.iter_mut().find(|h| h.id == host.id) {
            *existing = host.clone();
        } else {
            hosts.push(host.clone());
        }
        self.persist(&hosts)?;
        Ok(host)
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut hosts = self.hosts.lock().unwrap();
        hosts.retain(|h| h.id != id);
        self.persist(&hosts)
    }
}

#[tauri::command]
pub fn list_hosts(state: tauri::State<crate::AppState>) -> Vec<Host> {
    state.hosts.list()
}

#[tauri::command]
pub fn save_host(state: tauri::State<crate::AppState>, host: Host) -> Result<Host, String> {
    if host.name.trim().is_empty() || host.hostname.trim().is_empty() || host.user.trim().is_empty() {
        return Err("name, hostname, and user are required".into());
    }
    state.hosts.upsert(host)
}

#[tauri::command]
pub fn delete_host(state: tauri::State<crate::AppState>, id: String) -> Result<(), String> {
    state.hosts.delete(&id)
}
