//! Durable, disk-backed preferences that must survive an app reinstall.
//!
//! FamChat's hub connection (address, family word, your name) and this device's
//! stable identity live here, in the same OS config directory as the transcript —
//! *outside* the app bundle. Replacing FamChat.app on update leaves this file in
//! place, so the app reconnects to your hub and every room comes straight back.
//!
//! This is deliberately not in the webview's `localStorage`: that's a separate
//! store, and the whole point is that these values ride along with `history.json`
//! on the durable side, where an update can't touch them.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Everything needed to walk back into your family space after a reinstall.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Prefs {
    /// A stable per-device id (128-bit hex). The hub keys your DMs and room
    /// membership to this, so keeping it across reinstalls keeps your identity.
    #[serde(default)]
    pub device_id: String,
    /// The hub we last connected to, so we can reconnect automatically on launch.
    #[serde(default)]
    pub hub_address: String,
    #[serde(default)]
    pub hub_word: String,
    #[serde(default)]
    pub hub_name: String,
}

fn prefs_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "nyfe", "famchat")
        .ok_or_else(|| anyhow!("could not determine a config directory"))?;
    Ok(dirs.config_dir().join("prefs.json"))
}

/// Load prefs from disk (or defaults if absent/corrupt), guaranteeing a stable
/// `device_id` — one is minted and saved on first use.
pub fn load() -> Result<Prefs> {
    load_at(prefs_path()?)
}

/// Load from an explicit path (tests, or callers that keep prefs elsewhere).
pub fn load_at(path: impl Into<PathBuf>) -> Result<Prefs> {
    let path = path.into();
    let mut prefs: Prefs = if path.exists() {
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        // A convenience store, not a source of truth: tolerate a corrupt file by
        // starting fresh rather than refusing to open the app.
        serde_json::from_str(&json).unwrap_or_default()
    } else {
        Prefs::default()
    };
    if prefs.device_id.is_empty() {
        prefs.device_id = crate::new_conversation_id();
        save_at(&path, &prefs)?;
    }
    Ok(prefs)
}

/// Persist the hub connection fields, preserving the existing device id.
pub fn save_hub(address: &str, word: &str, name: &str) -> Result<Prefs> {
    let path = prefs_path()?;
    let mut prefs = load_at(path.clone())?;
    prefs.hub_address = address.to_string();
    prefs.hub_word = word.to_string();
    prefs.hub_name = name.to_string();
    save_at(&path, &prefs)?;
    Ok(prefs)
}

/// Forget the saved hub (the device id is kept, so identity survives).
pub fn clear_hub() -> Result<()> {
    let path = prefs_path()?;
    let mut prefs = load_at(path.clone())?;
    prefs.hub_address.clear();
    prefs.hub_word.clear();
    prefs.hub_name.clear();
    save_at(&path, &prefs)
}

fn save_at(path: &Path, prefs: &Prefs) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).context("creating config directory")?;
    }
    std::fs::write(path, serde_json::to_string_pretty(prefs)?).context("writing prefs file")?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mut p = md.permissions();
        p.set_mode(0o600);
        let _ = std::fs::set_permissions(path, p);
    }
}
#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("famchat-prefs-test-{name}.json"))
    }

    /// A device id is minted on first load and stays put across reloads.
    #[test]
    fn device_id_is_stable() {
        let p = tmp("stable");
        let _ = std::fs::remove_file(&p);
        let a = load_at(p.clone()).unwrap();
        assert_eq!(a.device_id.len(), 32, "128-bit id as 32 hex chars");
        let b = load_at(p.clone()).unwrap();
        assert_eq!(a.device_id, b.device_id, "id must survive a reload");
        let _ = std::fs::remove_file(&p);
    }

    /// Saving the hub keeps the device id, and reloading sees the hub — this is the
    /// "reinstall and your rooms come back" guarantee, in file form.
    #[test]
    fn hub_persists_and_keeps_identity() {
        let p = tmp("hub");
        let _ = std::fs::remove_file(&p);
        let first = load_at(p.clone()).unwrap();
        // Emulate save_hub against the explicit test path.
        let mut edited = first.clone();
        edited.hub_address = "192.168.1.50:9000".into();
        edited.hub_word = "acorn".into();
        edited.hub_name = "Mom".into();
        save_at(&p, &edited).unwrap();

        let again = load_at(p.clone()).unwrap();
        assert_eq!(again.device_id, first.device_id, "identity preserved");
        assert_eq!(again.hub_address, "192.168.1.50:9000");
        assert_eq!(again.hub_word, "acorn");
        assert_eq!(again.hub_name, "Mom");
        let _ = std::fs::remove_file(&p);
    }
}
