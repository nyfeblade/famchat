//! FamChat Hub protocol — a small private chat server for one family.
//!
//! The hub is a *trusted* relay + mailbox (a family's own always-on machine). Every
//! client opens one sealed channel to it (Noise, authenticated by the family word)
//! and signs in with a stable device id + display name. Through that single
//! connection the hub carries everything: a shared **Family** room, private 1-on-1
//! **DMs**, and named group **rooms** — each its own thread with its own history,
//! and each offline-capable (the hub holds what you missed and replays it).
//!
//! Messages ride as [`Frame::Group`](crate::Frame::Group) payloads inside that
//! channel. Every conversation has a monotonic `seq` and a per-person cursor, so a
//! member is replayed exactly what they haven't acknowledged.

use serde::{Deserialize, Serialize};

/// A person in the family directory.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Member {
    pub id: String,
    pub name: String,
}

/// What kind of conversation a thread is.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConvKind {
    /// A private 1-on-1 between two people.
    Dm,
    /// A named group room (the whole-family room, or a custom one).
    Room,
}

/// A conversation's metadata (who's in it and what it's called) — not its messages.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConvMeta {
    pub id: String,
    pub kind: ConvKind,
    /// Room name. Empty for a DM (the client shows the other person's name).
    pub title: String,
    pub members: Vec<String>,
}

/// The fixed id of the whole-family room everyone is a member of.
pub const FAMILY_ROOM: &str = "room:family";

/// Deterministic id for a 1-on-1 between two member ids, so both sides agree on it
/// regardless of who opens it first.
pub fn dm_id(a: &str, b: &str) -> String {
    if a <= b {
        format!("dm:{a}:{b}")
    } else {
        format!("dm:{b}:{a}")
    }
}

/// Client → Hub.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ClientMsg {
    /// Sign in with a stable device id and display name.
    Hello { id: String, name: String },
    /// Post a message to a conversation.
    Send { conv: String, text: String },
    /// Acknowledge receipt up to and including `seq` in a conversation.
    Ack { conv: String, seq: u64 },
    /// Open (creating if needed) a private 1-on-1 with `peer`.
    #[serde(rename = "opendm")]
    OpenDm { peer: String },
    /// Create a named room with the given members (you are added automatically).
    #[serde(rename = "createroom")]
    CreateRoom { title: String, members: Vec<String> },
}

/// Hub → Client.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ServerMsg {
    /// Sent right after Hello: who you are, the family directory, your
    /// conversations, and who's online. Message backlogs follow as `Msg`s.
    Welcome {
        you: String,
        members: Vec<Member>,
        convs: Vec<ConvMeta>,
        online: Vec<String>,
    },
    /// One delivered message — live, or replayed from a backlog on reconnect.
    Msg {
        conv: String,
        seq: u64,
        from: String,
        name: String,
        text: String,
        ts: i64,
    },
    /// A conversation you're now part of (a DM you opened, or a room you were added
    /// to).
    Conv { meta: ConvMeta },
    /// The family directory changed (someone new signed in).
    Members { members: Vec<Member> },
    /// Who is online right now.
    Presence { online: Vec<String> },
}

impl ClientMsg {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(b: &[u8]) -> Option<ClientMsg> {
        serde_json::from_slice(b).ok()
    }
}

impl ServerMsg {
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
    pub fn decode(b: &[u8]) -> Option<ServerMsg> {
        serde_json::from_slice(b).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_id_is_order_independent() {
        assert_eq!(dm_id("bob", "alice"), dm_id("alice", "bob"));
        assert_eq!(dm_id("alice", "bob"), "dm:alice:bob");
    }

    #[test]
    fn client_msgs_round_trip() {
        for m in [
            ClientMsg::Hello {
                id: "d1".into(),
                name: "Mom".into(),
            },
            ClientMsg::Send {
                conv: "room:family".into(),
                text: "hi 👋".into(),
            },
            ClientMsg::Ack {
                conv: "room:family".into(),
                seq: 5,
            },
            ClientMsg::OpenDm { peer: "d2".into() },
            ClientMsg::CreateRoom {
                title: "Trip".into(),
                members: vec!["d2".into(), "d3".into()],
            },
        ] {
            assert_eq!(ClientMsg::decode(&m.encode()), Some(m));
        }
    }

    #[test]
    fn server_msgs_round_trip() {
        for m in [
            ServerMsg::Welcome {
                you: "d1".into(),
                members: vec![Member {
                    id: "d1".into(),
                    name: "Mom".into(),
                }],
                convs: vec![ConvMeta {
                    id: FAMILY_ROOM.into(),
                    kind: ConvKind::Room,
                    title: "Family".into(),
                    members: vec!["d1".into()],
                }],
                online: vec!["d1".into()],
            },
            ServerMsg::Msg {
                conv: "dm:d1:d2".into(),
                seq: 3,
                from: "d2".into(),
                name: "Dad".into(),
                text: "on my way".into(),
                ts: 100,
            },
            ServerMsg::Conv {
                meta: ConvMeta {
                    id: "dm:d1:d2".into(),
                    kind: ConvKind::Dm,
                    title: "".into(),
                    members: vec!["d1".into(), "d2".into()],
                },
            },
            ServerMsg::Presence {
                online: vec!["d1".into(), "d2".into()],
            },
        ] {
            assert_eq!(ServerMsg::decode(&m.encode()), Some(m));
        }
    }
}
