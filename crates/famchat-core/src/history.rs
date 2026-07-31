//! Plaintext conversation history for FamChat.
//!
//! FamChat is a home-network chat, not a secrets vault: it keeps your transcript
//! on the device in a plain JSON file so you can scroll back, with no passphrase to
//! remember. Messages are still end-to-end encrypted *in flight* — this is only the
//! at-rest transcript, saved for convenience. The file is created `0600` where the
//! OS supports it, so other users on the machine can't casually read it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// One stored message in a conversation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoredMessage {
    /// Display name of the sender ("You" for our own messages, else the peer).
    pub from: String,
    pub text: String,
    /// Unix seconds (the caller stamps it).
    pub ts: i64,
    pub incoming: bool,
}

/// A conversation: a title plus its ordered messages.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Conversation {
    pub title: String,
    pub messages: Vec<StoredMessage>,
}

#[derive(Serialize, Deserialize, Default)]
struct Store {
    /// conversation id -> conversation. The id is stable (a group room id or a
    /// random per-conversation handle) — never the human display name, so two
    /// chats sharing a name never merge.
    conversations: BTreeMap<String, Conversation>,
    /// Saved peers (name -> address). `#[serde(default)]` keeps older stores
    /// loadable.
    #[serde(default)]
    contacts: BTreeMap<String, crate::contacts::Contact>,
}

/// A loaded, in-memory history that writes back to disk on every change.
pub struct History {
    store: Store,
    path: PathBuf,
}

/// A lightweight summary of a conversation for a sidebar list.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConversationSummary {
    pub id: String,
    pub title: String,
    pub last: String,
    pub count: usize,
    pub last_ts: i64,
}

fn history_path() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "nyfe", "famchat")
        .ok_or_else(|| anyhow!("could not determine a config directory"))?;
    Ok(dirs.config_dir().join("history.json"))
}

/// True if a history file already exists.
pub fn exists() -> Result<bool> {
    Ok(history_path()?.exists())
}

/// Permanently delete the on-disk history — every saved conversation. Irreversible;
/// a no-op (Ok) if there was nothing to delete.
pub fn delete() -> Result<()> {
    delete_at(history_path()?)
}

fn delete_at(path: PathBuf) -> Result<()> {
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("could not delete history {}: {e}", path.display())),
    }
}

impl History {
    /// Open (or create on first use) the on-disk history. No passphrase — FamChat
    /// keeps a plain local transcript.
    pub fn open() -> Result<History> {
        Self::open_at(history_path()?)
    }

    /// Open (or create) a history at an explicit path — for tests or callers that
    /// keep their transcript somewhere other than the default config location.
    pub fn open_at(path: impl Into<PathBuf>) -> Result<History> {
        let path = path.into();
        if !path.exists() {
            let h = History {
                store: Store::default(),
                path,
            };
            h.persist()?;
            return Ok(h);
        }
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        // A convenience transcript, not a source of truth: tolerate an empty or
        // corrupt file by starting fresh rather than refusing to open the app.
        let store: Store = serde_json::from_str(&json).unwrap_or_default();
        Ok(History { store, path })
    }

    /// Write the whole store back to disk. Called after every change.
    fn persist(&self) -> Result<()> {
        let path = &self.path;
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p).context("creating config directory")?;
            restrict_dir(p);
        }
        std::fs::write(path, serde_json::to_string_pretty(&self.store)?)
            .context("writing history file")?;
        restrict_file(path);
        Ok(())
    }

    /// Append a message to a conversation (creating it if new) and persist.
    pub fn append(&mut self, conv_id: &str, title: &str, msg: StoredMessage) -> Result<()> {
        let conv = self
            .store
            .conversations
            .entry(conv_id.to_string())
            .or_default();
        if conv.title.is_empty() || conv.title != title {
            conv.title = title.to_string();
        }
        conv.messages.push(msg);
        self.persist()
    }

    /// All conversations, most-recently-active first, as sidebar summaries.
    pub fn summaries(&self) -> Vec<ConversationSummary> {
        let mut v: Vec<ConversationSummary> = self
            .store
            .conversations
            .iter()
            .map(|(id, c)| {
                let last_msg = c.messages.last();
                ConversationSummary {
                    id: id.clone(),
                    title: c.title.clone(),
                    last: last_msg.map(|m| m.text.clone()).unwrap_or_default(),
                    count: c.messages.len(),
                    last_ts: last_msg.map(|m| m.ts).unwrap_or(0),
                }
            })
            .collect();
        v.sort_by(|a, b| b.last_ts.cmp(&a.last_ts));
        v
    }

    /// The full message list for one conversation.
    pub fn messages(&self, conv_id: &str) -> Vec<StoredMessage> {
        self.store
            .conversations
            .get(conv_id)
            .map(|c| c.messages.clone())
            .unwrap_or_default()
    }

    /// Delete a conversation and persist.
    pub fn forget(&mut self, conv_id: &str) -> Result<()> {
        self.store.conversations.remove(conv_id);
        self.persist()
    }

    /// Add or replace a saved peer, then write to disk.
    pub fn add_contact(&mut self, name: &str, address: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("contact name must not be empty");
        }
        self.store.contacts.insert(
            name.to_string(),
            crate::contacts::Contact {
                address: address.to_string(),
                fingerprint: None,
            },
        );
        self.persist()
    }

    /// Remove a saved peer; persists and returns whether it existed.
    pub fn remove_contact(&mut self, name: &str) -> Result<bool> {
        let existed = self.store.contacts.remove(name).is_some();
        if existed {
            self.persist()?;
        }
        Ok(existed)
    }

    /// Look up one saved peer by name.
    pub fn get_contact(&self, name: &str) -> Option<crate::contacts::Contact> {
        self.store.contacts.get(name).cloned()
    }

    /// All saved peers (name, contact), name-sorted.
    pub fn contacts(&self) -> Vec<(String, crate::contacts::Contact)> {
        self.store
            .contacts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
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

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Best-effort: we may not own a pre-existing / shared parent dir. The file's
    // own 0600 mode is the real protection, so a failure here is not fatal.
    if let Ok(md) = std::fs::metadata(path) {
        let mut p = md.permissions();
        p.set_mode(0o700);
        let _ = std::fs::set_permissions(path, p);
    }
}
#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    // Each test uses its own isolated file so they can run in parallel and never
    // touch the real config dir.
    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("famchat-hist-test-{name}.json"))
    }

    /// Messages persist across reopen, and summaries reflect the latest message.
    #[test]
    fn persists_and_reopens() {
        let p = tmp("reopen");
        let _ = std::fs::remove_file(&p);
        {
            let mut h = History::open_at(p.clone()).unwrap();
            h.append(
                "mom",
                "Mom",
                StoredMessage {
                    from: "You".into(),
                    text: "hey".into(),
                    ts: 100,
                    incoming: false,
                },
            )
            .unwrap();
            h.append(
                "mom",
                "Mom",
                StoredMessage {
                    from: "Mom".into(),
                    text: "hi back".into(),
                    ts: 101,
                    incoming: true,
                },
            )
            .unwrap();
        }
        let h2 = History::open_at(p.clone()).unwrap();
        let msgs = h2.messages("mom");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].text, "hey");
        assert_eq!(msgs[1].text, "hi back");
        assert!(msgs[1].incoming);
        let sums = h2.summaries();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].title, "Mom");
        assert_eq!(sums[0].last, "hi back");
        let _ = std::fs::remove_file(&p);
    }

    /// Two different conversations that share a display name never merge.
    #[test]
    fn same_title_different_id_never_merge() {
        let p = tmp("sametitle");
        let _ = std::fs::remove_file(&p);
        let mut h = History::open_at(p.clone()).unwrap();
        h.append(
            "id-a",
            "Kids",
            StoredMessage {
                from: "You".into(),
                text: "first".into(),
                ts: 1,
                incoming: false,
            },
        )
        .unwrap();
        h.append(
            "id-b",
            "Kids",
            StoredMessage {
                from: "You".into(),
                text: "second".into(),
                ts: 2,
                incoming: false,
            },
        )
        .unwrap();
        assert_eq!(h.messages("id-a").len(), 1);
        assert_eq!(h.messages("id-b").len(), 1);
        assert_eq!(
            h.summaries().len(),
            2,
            "same title must not collapse to one"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// The "delete all conversations" wipe removes the store and is idempotent.
    #[test]
    fn delete_removes_the_store_and_is_idempotent() {
        let p = tmp("delete");
        let _ = std::fs::remove_file(&p);
        History::open_at(p.clone()).unwrap();
        assert!(p.exists(), "opening must create the store");
        delete_at(p.clone()).unwrap();
        assert!(!p.exists(), "delete must remove the store from disk");
        delete_at(p.clone()).unwrap(); // deleting again is a clean no-op
    }

    #[test]
    fn conversation_ids_are_unique_and_opaque() {
        let a = crate::new_conversation_id();
        let b = crate::new_conversation_id();
        assert_ne!(a, b, "ids must not collide");
        assert_eq!(a.len(), 32, "128-bit id as 32 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
