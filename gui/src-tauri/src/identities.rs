//! Key identities available to present when connecting: whatever lives in
//! `~/.shh` as a private/`.pub` pair, plus a "Generate key" command that
//! writes a new Ed25519 pair the same way `shh-keygen` does.

use serde::Serialize;
use shh::crypto::{ed25519::PrivateKey, keyfile};

#[derive(Clone, Serialize)]
pub struct IdentityInfo {
    pub path: String,
    pub name: String,
    pub fingerprint: String,
}

/// `~/.shh`, the same home the `shh`/`shhd`/`shh-agent` binaries use.
fn shh_home() -> std::path::PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    std::path::PathBuf::from(home).join(".shh")
}

#[tauri::command]
pub fn list_identities() -> Vec<IdentityInfo> {
    let dir = shh_home();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if name.ends_with(".pub") || name.ends_with(".json") || name.ends_with(".sock") {
            continue;
        }
        let pub_path = {
            let mut p = path.clone().into_os_string();
            p.push(".pub");
            std::path::PathBuf::from(p)
        };
        let Ok(pub_text) = std::fs::read_to_string(&pub_path) else {
            continue;
        };
        let Ok((key, _comment)) = keyfile::decode_public(pub_text.trim()) else {
            continue;
        };
        out.push(IdentityInfo {
            path: path.to_string_lossy().into_owned(),
            name,
            fingerprint: key.fingerprint(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[tauri::command]
pub fn generate_identity(name: String, passphrase: Option<String>) -> Result<IdentityInfo, String> {
    let name = name.trim();
    // Reject `.`/`..` explicitly rather than relying on the `path.exists()`
    // check below to incidentally catch them: `..` resolves outside
    // `shh_home()` (to its parent, i.e. the user's home directory), and
    // that check only happens to block it today because the parent
    // directory itself exists -- a coincidence a future refactor of that
    // check could silently break.
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        return Err("invalid file name".into());
    }
    let dir = shh_home();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }

    let key = PrivateKey::generate();
    // Hold the passphrase in a zeroize-on-drop buffer so it does not linger in
    // freed heap memory, matching the core crate's handling of key material.
    let passphrase = passphrase
        .filter(|p| !p.is_empty())
        .map(zeroize::Zeroizing::new);
    let encoded = keyfile::encode_private_protected(&key, "", passphrase.as_deref().map(|s| s.as_str()))
        .map_err(|e| e.to_string())?;
    let pub_line = keyfile::encode_public(&key.public(), "");

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = opts.open(&path).map_err(|e| e.to_string())?;
        f.write_all(encoded.as_bytes()).map_err(|e| e.to_string())?;
    }
    let pub_path = {
        let mut p = path.clone().into_os_string();
        p.push(".pub");
        std::path::PathBuf::from(p)
    };
    std::fs::write(&pub_path, &pub_line).map_err(|e| e.to_string())?;

    Ok(IdentityInfo {
        path: path.to_string_lossy().into_owned(),
        name: name.to_string(),
        fingerprint: key.public().fingerprint(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_rejects_dot_and_dotdot() {
        assert!(generate_identity(".".into(), None).is_err());
        assert!(generate_identity("..".into(), None).is_err());
        assert!(generate_identity("/etc/passwd".into(), None).is_err());
        assert!(generate_identity("a/../../etc".into(), None).is_err());
    }
}
