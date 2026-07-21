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
        let hosts: Vec<Host> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let hosts = drop_invalid_hosts(hosts);
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

/// `hostname` ends up verbatim in a known_hosts line on first contact
/// (`client::verify_host_key` -> `keyfile::known_hosts_line`); an embedded
/// newline would let it inject an *extra* line under a name of the
/// attacker's choosing, poisoning the pinned key for an unrelated host.
/// Reject control characters in every field that's rendered into a file or a
/// session, not just hostname, since the IPC boundary is callable directly
/// (not just through the form the UI presents).
/// `save_host` validates on the way in, but that only covers entries written
/// through this app's own IPC command -- a file written by an older build
/// (before validation existed), or placed there some other way, could still
/// carry a poisoned hostname. Re-validate on load and drop anything that
/// wouldn't pass `save_host` today, rather than trusting the file's prior
/// contents implicitly.
fn drop_invalid_hosts(hosts: Vec<Host>) -> Vec<Host> {
    hosts.into_iter().filter(|h| validate_host(h).is_ok()).collect()
}

fn validate_host(host: &Host) -> Result<(), String> {
    if host.name.trim().is_empty() || host.hostname.trim().is_empty() || host.user.trim().is_empty() {
        return Err("name, hostname, and user are required".into());
    }
    let fields = [&host.name, &host.hostname, &host.user]
        .into_iter()
        .chain(host.identity.iter());
    if fields.flat_map(|s| s.chars()).any(|c| c.is_control()) {
        return Err("fields may not contain control characters".into());
    }
    // known_hosts lookups split a line on the first whitespace run
    // (keyfile::known_hosts_line consumers use `char::is_whitespace`), so an
    // ordinary space in `hostname` isn't a cross-host injection like a
    // newline, but it does corrupt the line this host's own TOFU entry gets
    // written as -- the lookup that's supposed to find it again never will,
    // so the host would ask "is this the right key?" on every connection.
    // `user` (an SSH login name) has no legitimate reason to contain
    // whitespace either; `name` is a free-form display label and `identity`
    // is a filesystem path, both of which may legitimately contain spaces.
    if host.hostname.chars().any(char::is_whitespace) || host.user.chars().any(char::is_whitespace) {
        return Err("hostname and user may not contain whitespace".into());
    }
    Ok(())
}

#[tauri::command]
pub fn save_host(state: tauri::State<crate::AppState>, host: Host) -> Result<Host, String> {
    validate_host(&host)?;
    state.hosts.upsert(host)
}

#[tauri::command]
pub fn delete_host(state: tauri::State<crate::AppState>, id: String) -> Result<(), String> {
    state.hosts.delete(&id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(hostname: &str) -> Host {
        Host {
            id: "1".into(),
            name: "box".into(),
            hostname: hostname.into(),
            port: 22,
            user: "me".into(),
            identity: None,
        }
    }

    #[test]
    fn validate_host_rejects_a_known_hosts_injection_attempt() {
        // A newline in `hostname` would otherwise let a saved host inject an
        // extra known_hosts line under an attacker-chosen name.
        assert!(validate_host(&host("evil.example\nreal.example")).is_err());
        assert!(validate_host(&host("evil.example\rreal.example")).is_err());
        assert!(validate_host(&host("plain.example")).is_ok());
    }

    #[test]
    fn validate_host_rejects_control_chars_in_any_field() {
        let mut h = host("plain.example");
        h.name = "box\0".into();
        assert!(validate_host(&h).is_err());

        let mut h = host("plain.example");
        h.user = "me\x1b[31m".into();
        assert!(validate_host(&h).is_err());

        let mut h = host("plain.example");
        h.identity = Some("/home/me/.shh/id\n".into());
        assert!(validate_host(&h).is_err());
    }

    #[test]
    fn validate_host_rejects_whitespace_in_hostname_and_user() {
        // A space in hostname doesn't cross-poison another host's line the
        // way a newline does, but it does corrupt this host's own
        // known_hosts entry: keyfile's lookups split on the first
        // whitespace run, so the entry could never be found again.
        assert!(validate_host(&host("plain example")).is_err());
        assert!(validate_host(&host("plain\texample")).is_err());

        let mut h = host("plain.example");
        h.user = "me too".into();
        assert!(validate_host(&h).is_err());

        // Free-form fields may legitimately contain spaces.
        let mut h = host("plain.example");
        h.name = "My Prod Box".into();
        assert!(validate_host(&h).is_ok());
        h.identity = Some("/home/me/My Keys/id".into());
        assert!(validate_host(&h).is_ok());
    }

    #[test]
    fn validate_host_requires_non_empty_core_fields() {
        assert!(validate_host(&host("")).is_err());
        let mut h = host("plain.example");
        h.name = "  ".into();
        assert!(validate_host(&h).is_err());
    }

    /// A file written before validation existed (or placed there some other
    /// way) shouldn't get a free pass just because it's already on disk --
    /// `load()` must re-validate, not just `save_host`.
    #[test]
    fn drop_invalid_hosts_filters_poisoned_entries_from_disk() {
        let good = host("real.example");
        let poisoned = host("evil.example\nreal.example");
        let kept = drop_invalid_hosts(vec![good.clone(), poisoned]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].hostname, good.hostname);
    }
}
