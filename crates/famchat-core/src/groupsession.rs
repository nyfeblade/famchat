//! Group messaging layer — the host-blind coordination on top of [`crate::group`]
//! Sender Keys and the pairwise sealed channels.
//!
//! A group is a hub: every member holds one pairwise [`crate::channel`] to the
//! host, and the host relays. The catch is confidentiality *from the host*: the
//! host must forward messages it cannot read. Two message kinds make that work:
//!
//! * Group **text** is encrypted once with the sender's Sender Key (symmetric,
//!   held only by members). The host broadcasts the ciphertext; it has no key.
//! * A sender's **key distribution** — which contains the secret chain key — must
//!   never reach the host in readable form. So each member *seals* its
//!   distribution to each recipient's public key (an X25519 + ChaCha20-Poly1305
//!   sealed box). The host routes the opaque sealed blob to its target; only the
//!   holder of the recipient private key can open it.
//!
//! The host therefore learns the membership (who is in the room) and relays
//! traffic, but never a sender key or a plaintext. This module is the member-side
//! state machine and the [`GroupMsg`] wire format the relay shuttles inside
//! [`crate::message::Frame::Group`]; the networked relay task lives a layer up.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::group::{ReceiverState, SenderKeyDistribution, SenderKeyState};

/// A per-session member identifier (random; not a long-term identity).
pub type MemberId = [u8; 16];

/// HKDF label for the sealed-box KDF (domain separation).
const SEALEDBOX_INFO: &[u8] = b"ciphext-group-sealedbox-v1";

// Wire tags for [`GroupMsg`].
const G_HELLO: u8 = 0x01;
const G_ROSTER: u8 = 0x02;
const G_KEYFOR: u8 = 0x03;
const G_TEXT: u8 = 0x04;

// ===========================================================================
// Sealed box — anonymous public-key encryption for host-blind key distribution
// ===========================================================================

/// Encrypt `plaintext` so that only the holder of the private key matching
/// `recipient_pub` can read it. A fresh ephemeral X25519 keypair is used per
/// call, so the derived AEAD key is unique to this message and a fixed nonce is
/// safe. Wire = ephemeral_public(32) || ChaCha20-Poly1305 ciphertext.
fn seal_to(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let eph = StaticSecret::from(eph_bytes);
    eph_bytes.zeroize();
    let eph_pub = PublicKey::from(&eph);

    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_pub));
    let mut key = sealedbox_kdf(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();

    let ct = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
        // Encryption is infallible for a valid key/nonce; not attacker-reachable.
        .expect("ChaCha20-Poly1305 seal cannot fail for a valid key and nonce");

    let mut out = Vec::with_capacity(32 + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Open a sealed box addressed to us. Returns an error on any malformed input or
/// authentication failure — never panics.
fn open_sealed(my_secret: &StaticSecret, wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < 32 + 16 {
        bail!("group: sealed box too short");
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&wire[..32]);

    let shared = my_secret.diffie_hellman(&PublicKey::from(eph_pub));
    let mut key = sealedbox_kdf(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();

    cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), &wire[32..])
        .map_err(|_| anyhow!("group: sealed box authentication failed"))
}

fn sealedbox_kdf(ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut k = [0u8; 32];
    hk.expand(SEALEDBOX_INFO, &mut k)
        .expect("HKDF expand of 32 bytes is within bounds");
    k
}

// ===========================================================================
// Group protocol messages (carried inside Frame::Group over pairwise channels)
// ===========================================================================

/// A message the relay shuttles between members. Only [`GroupMsg::KeyFor`]'s
/// `sealed` bytes and [`GroupMsg::Text`]'s `ct` bytes carry secrets — both are
/// opaque to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMsg {
    /// A joining member announces its id and public key to the host.
    Hello { id: MemberId, public: [u8; 32] },
    /// The host tells members the current roster.
    Roster { members: Vec<(MemberId, [u8; 32])> },
    /// A sealed Sender-Key distribution from `from`, addressed to `to`.
    KeyFor {
        to: MemberId,
        from: MemberId,
        sealed: Vec<u8>,
    },
    /// Group text: `from`'s Sender-Key ciphertext, to be broadcast.
    Text { from: MemberId, ct: Vec<u8> },
}

impl GroupMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            GroupMsg::Hello { id, public } => {
                v.push(G_HELLO);
                v.extend_from_slice(id);
                v.extend_from_slice(public);
            }
            GroupMsg::Roster { members } => {
                v.push(G_ROSTER);
                v.extend_from_slice(&(members.len() as u16).to_be_bytes());
                for (id, pk) in members {
                    v.extend_from_slice(id);
                    v.extend_from_slice(pk);
                }
            }
            GroupMsg::KeyFor { to, from, sealed } => {
                v.push(G_KEYFOR);
                v.extend_from_slice(to);
                v.extend_from_slice(from);
                v.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
                v.extend_from_slice(sealed);
            }
            GroupMsg::Text { from, ct } => {
                v.push(G_TEXT);
                v.extend_from_slice(from);
                v.extend_from_slice(ct);
            }
        }
        v
    }

    /// Parse a group message. All framing is length-checked before indexing;
    /// malformed input returns an error and never panics.
    pub fn decode(bytes: &[u8]) -> Result<GroupMsg> {
        let (&tag, rest) = bytes
            .split_first()
            .ok_or_else(|| anyhow!("group: empty message"))?;
        match tag {
            G_HELLO => {
                if rest.len() != 16 + 32 {
                    bail!("group: bad Hello length");
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&rest[..16]);
                let mut public = [0u8; 32];
                public.copy_from_slice(&rest[16..48]);
                Ok(GroupMsg::Hello { id, public })
            }
            G_ROSTER => {
                if rest.len() < 2 {
                    bail!("group: short Roster");
                }
                let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let body = &rest[2..];
                if body.len() != count * 48 {
                    bail!("group: Roster length mismatch");
                }
                let mut members = Vec::with_capacity(count);
                for chunk in body.chunks_exact(48) {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&chunk[..16]);
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&chunk[16..48]);
                    members.push((id, pk));
                }
                Ok(GroupMsg::Roster { members })
            }
            G_KEYFOR => {
                if rest.len() < 16 + 16 + 4 {
                    bail!("group: short KeyFor");
                }
                let mut to = [0u8; 16];
                to.copy_from_slice(&rest[..16]);
                let mut from = [0u8; 16];
                from.copy_from_slice(&rest[16..32]);
                let slen = u32::from_be_bytes([rest[32], rest[33], rest[34], rest[35]]) as usize;
                let sealed = &rest[36..];
                if sealed.len() != slen {
                    bail!("group: KeyFor sealed length mismatch");
                }
                Ok(GroupMsg::KeyFor {
                    to,
                    from,
                    sealed: sealed.to_vec(),
                })
            }
            G_TEXT => {
                if rest.len() < 16 {
                    bail!("group: short Text");
                }
                let mut from = [0u8; 16];
                from.copy_from_slice(&rest[..16]);
                Ok(GroupMsg::Text {
                    from,
                    ct: rest[16..].to_vec(),
                })
            }
            other => bail!("group: unknown message type {other:#04x}"),
        }
    }
}

// ===========================================================================
// Member state machine
// ===========================================================================

/// A member's group state: its own Sender Key, its member keypair for receiving
/// sealed distributions, the roster it knows, and a [`ReceiverState`] per peer.
pub struct GroupMember {
    id: MemberId,
    secret: StaticSecret,
    public: [u8; 32],
    sender: SenderKeyState,
    roster: BTreeMap<MemberId, [u8; 32]>,
    receivers: BTreeMap<MemberId, ReceiverState>,
    keyed_to: BTreeSet<MemberId>,
}

impl GroupMember {
    /// Create a fresh member (random id + member keypair + Sender Key).
    pub fn new() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        let secret = StaticSecret::from(sk_bytes);
        sk_bytes.zeroize();
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            id,
            secret,
            public,
            sender: SenderKeyState::new(),
            roster: BTreeMap::new(),
            receivers: BTreeMap::new(),
            keyed_to: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> MemberId {
        self.id
    }
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The message a joining member sends to the host so it can be added to the
    /// roster.
    pub fn hello(&self) -> GroupMsg {
        GroupMsg::Hello {
            id: self.id,
            public: self.public,
        }
    }

    /// Apply a roster update from the host. For every member we have not yet sent
    /// our Sender Key to, produce a sealed `KeyFor` addressed to them (so they
    /// can decrypt our future messages). The relay routes each to its target.
    pub fn on_roster(&mut self, members: &[(MemberId, [u8; 32])]) -> Vec<GroupMsg> {
        let mut out = Vec::new();
        for (mid, pk) in members {
            self.roster.insert(*mid, *pk);
            if *mid == self.id || self.keyed_to.contains(mid) {
                continue;
            }
            let sealed = seal_to(pk, &self.sender.distribution().encode());
            out.push(GroupMsg::KeyFor {
                to: *mid,
                from: self.id,
                sealed,
            });
            self.keyed_to.insert(*mid);
        }
        out
    }

    /// Receive a sealed Sender-Key distribution addressed to us and install the
    /// sending peer's [`ReceiverState`].
    pub fn on_key_for(&mut self, from: MemberId, sealed: &[u8]) -> Result<()> {
        let dist_bytes = open_sealed(&self.secret, sealed)?;
        let dist = SenderKeyDistribution::decode(&dist_bytes)
            .map_err(|e| anyhow!("group: bad key distribution: {e}"))?;
        self.receivers
            .insert(from, ReceiverState::from_distribution(&dist));
        Ok(())
    }

    /// Encrypt a group text with our Sender Key. Broadcast the result.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> GroupMsg {
        GroupMsg::Text {
            from: self.id,
            ct: self.sender.encrypt(plaintext),
        }
    }

    /// Decrypt a group text from `from`. Errors if we hold no key for that sender
    /// (they never announced to us) or the ciphertext fails to verify/decrypt.
    pub fn on_text(&mut self, from: MemberId, ct: &[u8]) -> Result<Vec<u8>> {
        let rs = self
            .receivers
            .get_mut(&from)
            .ok_or_else(|| anyhow!("group: no sender key for that member"))?;
        rs.decrypt(ct).map_err(|e| anyhow!("group: {e}"))
    }
}

impl Default for GroupMember {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three members exchange keys through a simulated host relay and then send
    /// group text that every other member decrypts — while the host, holding
    /// only the relayed bytes, can read none of it.
    #[test]
    fn three_member_group_is_host_blind() {
        let mut a = GroupMember::new();
        let mut b = GroupMember::new();
        let mut c = GroupMember::new();

        // The host learns the roster from each Hello (public info only).
        let roster: Vec<(MemberId, [u8; 32])> = vec![
            (a.id(), a.public()),
            (b.id(), b.public()),
            (c.id(), c.public()),
        ];

        // Each member seals its Sender Key to every other member.
        let mut keyfors: Vec<GroupMsg> = Vec::new();
        keyfors.extend(a.on_roster(&roster));
        keyfors.extend(b.on_roster(&roster));
        keyfors.extend(c.on_roster(&roster));

        // The host routes each KeyFor to its target WITHOUT being able to read it.
        // Prove host-blindness: the sealed bytes are not the plaintext distribution.
        let a_dist_plain = a.sender.distribution().encode();
        for m in &keyfors {
            if let GroupMsg::KeyFor { from, sealed, .. } = m {
                if *from == a.id() {
                    assert_ne!(
                        sealed.as_slice(),
                        a_dist_plain.as_slice(),
                        "host must not see a plaintext key"
                    );
                }
            }
        }
        for m in &keyfors {
            if let GroupMsg::KeyFor { to, from, sealed } = m {
                // encode/decode round-trip through the wire, like the real relay.
                let wire = m.encode();
                let GroupMsg::KeyFor {
                    to: to2,
                    from: from2,
                    sealed: sealed2,
                } = GroupMsg::decode(&wire).unwrap()
                else {
                    panic!("expected KeyFor")
                };
                assert_eq!((*to, *from, sealed.clone()), (to2, from2, sealed2));
                let target = if *to == a.id() {
                    &mut a
                } else if *to == b.id() {
                    &mut b
                } else {
                    &mut c
                };
                target.on_key_for(*from, sealed).unwrap();
            }
        }

        // Now group text flows. a -> everyone.
        let msg = a.encrypt(b"meet at the vault, 9pm");
        let (from, ct) = match &msg {
            GroupMsg::Text { from, ct } => (*from, ct.clone()),
            _ => panic!(),
        };
        // Host relays ct to b and c; it can't read it.
        assert_ne!(
            ct,
            b"meet at the vault, 9pm".to_vec(),
            "text must be ciphertext"
        );
        assert_eq!(b.on_text(from, &ct).unwrap(), b"meet at the vault, 9pm");
        assert_eq!(c.on_text(from, &ct).unwrap(), b"meet at the vault, 9pm");

        // And b -> everyone, proving every direction works.
        let msg2 = b.encrypt(b"on my way");
        let (from2, ct2) = match &msg2 {
            GroupMsg::Text { from, ct } => (*from, ct.clone()),
            _ => panic!(),
        };
        assert_eq!(a.on_text(from2, &ct2).unwrap(), b"on my way");
        assert_eq!(c.on_text(from2, &ct2).unwrap(), b"on my way");
    }

    #[test]
    fn wrong_recipient_cannot_open_sealed_key() {
        let mut a = GroupMember::new();
        let b = GroupMember::new();
        let mut eve = GroupMember::new();
        let roster = vec![(a.id(), a.public()), (b.id(), b.public())];
        let keyfors = a.on_roster(&roster);
        // A sealed A's key to B. Eve (wrong private key) must not open it.
        for m in keyfors {
            if let GroupMsg::KeyFor { from, sealed, .. } = m {
                assert!(eve.on_key_for(from, &sealed).is_err());
            }
        }
    }

    #[test]
    fn malformed_group_messages_are_rejected() {
        assert!(GroupMsg::decode(&[]).is_err());
        assert!(GroupMsg::decode(&[0xFF, 1, 2, 3]).is_err());
        assert!(GroupMsg::decode(&[G_HELLO, 1, 2]).is_err()); // too short
        assert!(GroupMsg::decode(&[G_TEXT, 0, 0]).is_err()); // no member id
                                                             // A truncated sealed box fails to open, not panics.
        let mut m = GroupMember::new();
        assert!(m.on_key_for([0u8; 16], &[0u8; 10]).is_err());
    }
}
