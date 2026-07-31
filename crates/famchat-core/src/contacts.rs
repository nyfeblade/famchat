//! Address-book value types.
//!
//! The address book itself is stored **encrypted at rest** inside the history
//! store — see [`crate::history::History`] (`add_contact` / `remove_contact` /
//! `get_contact` / `contacts`). It is sealed under the same
//! Argon2id -> XChaCha20-Poly1305 scheme and master passphrase as conversation
//! history, so contact names, addresses (including `.onion`) and pinned
//! fingerprints — a social graph — never touch the disk in the clear. This
//! module only defines the data shapes; it performs no I/O. Code words are never
//! stored at all; they stay in your head.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct Contact {
    /// Host:port for a direct link, or a `.onion` address for a Tor link.
    pub address: String,
    /// Pinned peer fingerprint, if known. Enforced on connect.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Book {
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_roundtrips_through_serde() {
        let mut book = Book::default();
        book.contacts.insert(
            "spydershard".into(),
            Contact {
                address: "abcdefghij234567.onion:9000".into(),
                fingerprint: Some("537B 45AB".into()),
            },
        );
        book.contacts.insert(
            "laptop".into(),
            Contact {
                address: "laptop.local".into(),
                fingerprint: None,
            },
        );
        let json = serde_json::to_string(&book).unwrap();
        let back: Book = serde_json::from_str(&json).unwrap();
        assert_eq!(back.contacts.len(), 2);
        assert_eq!(
            back.contacts["spydershard"].address,
            "abcdefghij234567.onion:9000"
        );
        assert_eq!(back.contacts["laptop"].fingerprint, None);
    }
}
