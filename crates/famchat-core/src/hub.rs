//! FamChat Hub protocol — the messages a client and an always-on hub exchange.
//!
//! The hub is a *trusted* relay + mailbox (typically a family's own always-on
//! laptop): every client opens a normal sealed channel to it (Noise, authenticated
//! by the family word), and these messages ride inside that channel as
//! [`Frame::Group`](crate::Frame::Group) payloads. Because the hub is the endpoint
//! of each client's sealed channel, it can read the messages — that's what lets it
//! hold them for people who are offline and deliver them when they return.
//!
//! Delivery model: the hub keeps one append-only log with a monotonic `seq`, and a
//! per-person cursor (the highest `seq` they've acknowledged). When you connect it
//! replays everything past your cursor, then streams live; you `Ack` as you receive
//! so the hub knows what it can stop keeping for you.

use serde::{Deserialize, Serialize};

/// Client → Hub.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ClientMsg {
    /// First message after connecting: a stable per-device id and display name.
    Hello { id: String, name: String },
    /// Post a chat message to the family room.
    Send { text: String },
    /// "I have received everything up to and including this seq." Lets the hub
    /// advance your cursor and stop re-sending delivered messages.
    Ack { seq: u64 },
}

/// Hub → Client.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ServerMsg {
    /// Acknowledges a [`ClientMsg::Hello`].
    Welcome,
    /// One delivered chat message — live, or replayed from the backlog on reconnect.
    Msg {
        seq: u64,
        from: String,
        name: String,
        text: String,
        ts: i64,
    },
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
    fn client_msgs_round_trip() {
        for m in [
            ClientMsg::Hello {
                id: "dev1".into(),
                name: "Mom".into(),
            },
            ClientMsg::Send {
                text: "hi 👋".into(),
            },
            ClientMsg::Ack { seq: 42 },
        ] {
            assert_eq!(ClientMsg::decode(&m.encode()), Some(m));
        }
    }

    #[test]
    fn server_msgs_round_trip() {
        for m in [
            ServerMsg::Welcome,
            ServerMsg::Msg {
                seq: 7,
                from: "dev2".into(),
                name: "Dad".into(),
                text: "on my way".into(),
                ts: 1000,
            },
        ] {
            assert_eq!(ServerMsg::decode(&m.encode()), Some(m));
        }
    }

    #[test]
    fn garbage_decodes_to_none() {
        assert_eq!(ClientMsg::decode(b"not json"), None);
        assert_eq!(ServerMsg::decode(b"{}"), None);
    }
}
