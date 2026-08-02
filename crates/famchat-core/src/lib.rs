//! FamChat core — a simple, encrypted LAN chat engine.
//!
//! A serverless, end-to-end encrypted messenger for a home network. Two people —
//! or a family group — authenticate with a shared word (SPAKE2 PAKE) and talk over
//! a Noise-sealed channel with forward secrecy, carried on a direct TCP socket.
//!
//! Nothing here talks to a server, because there is no server.

// A tripwire, not a lint: `forbid` (unlike `deny`) cannot be locally overridden by
// an `#[allow(unsafe_code)]`, so the build fails outright if anyone introduces
// `unsafe` in this crate. The whole engine is safe Rust and stays that way.
#![forbid(unsafe_code)]

pub mod channel;
pub mod contacts;
pub mod cover;
pub mod group;
pub mod grouphost;
pub mod groupsession;
pub mod history;
pub mod hub;
pub mod identity;
pub mod message;
pub mod prefs;
pub mod ratchet;
pub mod session;
pub mod transport;
pub mod wire;

pub use channel::{SealedChannel, SealedReceiver, SealedSender};
pub use cover::{spawn as spawn_cover, CoverChannel, CoverConfig, CELL_SIZE};
pub use group::{GroupError, ReceiverState, SenderKeyDistribution, SenderKeyState};
pub use grouphost::{GroupClient, GroupHandle, GroupHost, GroupReceiver};
pub use groupsession::{GroupMember, GroupMsg, MemberId};
pub use history::{Conversation, ConversationSummary, History, StoredMessage};
pub use hub::{dm_id, ClientMsg, ConvKind, ConvMeta, Member, ServerMsg, FAMILY_ROOM};
pub use identity::{fingerprint, Identity};
pub use message::{
    human_size, FileGate, Frame, Incoming, CHUNK_SIZE, MAX_CONCURRENT_FILES, MAX_FILE_SIZE,
};
pub use prefs::Prefs;
pub use ratchet::{DoubleRatchet, RatchetError, HEADER_LEN, MAX_SKIP};
pub use session::{Auth, Established, Link, SessionInfo};
pub use transport::{AnyStream, Listener, TcpTransport, Transport};

/// A fresh, unguessable identifier for a kept conversation (128 bits, hex).
///
/// Conversations are keyed by this stable id — never by the human display name —
/// so two chats that happen to share a name never merge into one transcript.
pub fn new_conversation_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
