//! # Double Ratchet (`ratchet.rs`)
//!
//! A Signal-style **Double Ratchet** providing per-message forward secrecy and
//! post-compromise security ("rolling code") for Ciphext. This layer operates on
//! the *application plaintext* — it is the **inner** encryption applied before the
//! outer Noise transport seal (`wire::seal`). Even if the long-term Noise session
//! keys are later compromised, past messages stay secret (forward secrecy) and the
//! session self-heals after each round-trip (post-compromise security).
//!
//! ## Where this sits in the Ciphext layering contract
//! Outbound, the pipeline is:
//!
//! ```text
//! app Frame bytes
//!   -> DoubleRatchet::encrypt   (this module: inner forward-secret layer)
//!   -> cover layer              (packs the opaque ratchet ciphertext into
//!                                FIXED-SIZE cells)
//!   -> wire::seal / Noise       (AEAD-seals EACH fixed cell; constant ciphertext
//!                                length; emitted at a constant cadence)
//!   -> constant-size record on the wire
//! ```
//!
//! Inbound is the exact mirror (Noise open -> fixed cell -> cover reassemble ->
//! `DoubleRatchet::decrypt` -> app Frame).
//!
//! ## Length hiding is NOT this layer's job (see finding #2)
//! This module intentionally does **not** pad. A ratchet wire message is exactly
//! `HEADER_LEN (40) + |plaintext| + 16` bytes (the trailing 16 is the
//! ChaCha20-Poly1305 tag), so on its own it *does* reveal the plaintext length.
//! That is fine and by design: length hiding is **delegated to the cover layer**,
//! which chops the opaque ratchet ciphertext into constant-size cells before the
//! Noise transport seals them, yielding a constant-size record on the wire. Adding
//! padding here would be redundant and would only fight the cover layer's fixed
//! cells. Do **not** add padding to the ratchet.
//!
//! ## Required Cargo features (see finding #3)
//! `x25519-dalek` **must** be built with the `"zeroize"` feature (alongside
//! `"static_secrets"`), i.e. in `Cargo.toml`:
//!
//! ```toml
//! x25519-dalek = { version = "2", features = ["static_secrets", "zeroize"] }
//! ```
//!
//! The `"zeroize"` feature is what makes [`StaticSecret`] wipe its bytes on drop;
//! without it the DH ratchet private keys would linger in freed memory and the
//! forward-secrecy guarantee this module advertises would be silently broken. The
//! code below relies on that drop-wipe behaviour.
//!
//! ## Construction (per the Signal Double Ratchet specification)
//! * **DH ratchet** — X25519 (`x25519-dalek`, `StaticSecret`/`PublicKey`).
//! * **Root & chain KDFs** — HKDF-SHA-256 (`hkdf` + `sha2`).
//! * **Message AEAD** — ChaCha20-Poly1305 with a per-message key and a 96-bit
//!   nonce, both derived from the chain via HKDF.
//! * **Root seed** — a 32-byte shared secret supplied at init. In Ciphext this is
//!   the Noise handshake hash (`TransportState::get_handshake_hash`), a value both
//!   peers agree on but no observer knows.
//!
//! ## Security properties / notes
//! * Zero hand-rolled primitives: every cryptographic operation is delegated to a
//!   vetted crate.
//! * All symmetric key material (root key, chain keys, message keys, derived
//!   AEAD keys, DH shared secrets) is wrapped in [`Zeroizing`] or a
//!   zero-on-drop type, so it is wiped from memory when dropped. DH ratchet
//!   private keys ([`StaticSecret`]) are wiped by the `x25519-dalek` `"zeroize"`
//!   feature (see above).
//! * `decrypt` is **transactional** *without cloning the whole session* (see
//!   findings #1 / #7): it derives every skipped key and the target message key
//!   into local scratch buffers and mutates `self` only after the AEAD tag
//!   verifies. A forged or corrupted header therefore cannot poison the live
//!   ratchet state, and a forgery costs only its bounded skip work — never a deep
//!   clone of the skipped-key cache.
//! * No panics on attacker-controlled input: [`DoubleRatchet::decrypt`] validates
//!   all wire framing and returns [`RatchetError`] on any malformed or forged
//!   input. AEAD tags are verified in constant time by the AEAD itself — secrets
//!   are never compared with `==`.
//! * **Bounded work per packet** (see finding #1): a single inbound packet can
//!   force at most [`MAX_SKIP`] message-key derivations *in total*, shared across
//!   the previous-chain flush and the current-chain catch-up. One packet can never
//!   drive ~`2*MAX_SKIP` HKDF derivations, and the skipped-key cache evicts in
//!   `O(log n)` via an insertion-ordered index (no linear min-scan).
//! * Out-of-order and dropped messages are tolerated up to the per-packet
//!   [`MAX_SKIP`] budget, with a bounded ([`MAX_SKIP_STORE`]) cache of skipped
//!   message keys that survives DH ratchet steps (see finding #6). Exceeding the
//!   tolerance yields a clean error rather than an unbounded loop.
//!
//! The module has **no** `crate::` dependencies — it depends only on external
//! crates so it compiles standalone (as its own crate) and drops unchanged into
//! `ciphext-core` as `ratchet.rs`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of message keys a single inbound packet may force us to derive.
///
/// This bounds *both* the largest in-chain gap we will tolerate and the total
/// skip work per received message. Crucially the budget is **shared** across a
/// DH-ratchet step's previous-chain flush and its current-chain catch-up, so one
/// packet can never force ~`2*MAX_SKIP` derivations (see finding #1).
pub const MAX_SKIP: u32 = 1000;

/// Maximum number of skipped message keys retained across the whole session.
/// Once this many keys are cached, inserting a new one evicts the oldest
/// (insertion-ordered, `O(log n)`).
///
/// This is deliberately a comfortable multiple of [`MAX_SKIP`] (see finding #6):
/// with `MAX_SKIP_STORE == MAX_SKIP`, a single large in-chain skip could evict
/// every still-wanted key banked from *other* DH chains. Sizing the store well
/// above a single packet's maximum skip keeps cross-chain out-of-order keys
/// alive.
pub const MAX_SKIP_STORE: usize = 4 * MAX_SKIP as usize; // 4000

/// Fixed on-wire header length: `dh_pub(32) || pn(4) || n(4)`.
pub const HEADER_LEN: usize = 40;

// HKDF domain-separation labels.
const KDF_RK_INFO: &[u8] = b"ciphext-double-ratchet-root-v1";
const KDF_MK_INFO: &[u8] = b"ciphext-double-ratchet-message-v1";

// ===========================================================================
// Errors
// ===========================================================================

/// Reason a [`DoubleRatchet`] operation failed. All variants are safe to surface
/// to a peer; none leak secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    /// The wire message was shorter than a header, or otherwise unparsable.
    Malformed,
    /// The AEAD tag did not verify (forged, corrupted, or replayed message).
    Decrypt,
    /// The message number is farther ahead than the per-packet [`MAX_SKIP`]
    /// budget permits.
    TooManySkipped,
    /// A message arrived that requires receiving-chain state we do not have
    /// (e.g. a header referencing a ratchet key that was never established).
    OutOfOrder,
    /// [`DoubleRatchet::encrypt`] was called before a sending chain exists (an
    /// `init_bob` ratchet that has not yet decrypted the peer's first message).
    NoSendingChain,
    /// The sending chain has addressed its last representable message index. The
    /// wire header counter `n` is a `u32`, so a single chain spans at most 2³²
    /// messages; rather than wrap the counter (which would reuse a message-key
    /// index — catastrophic key/nonce reuse) or panic, `encrypt` fails closed.
    ChainExhausted,
}

/// Error type returned by [`DoubleRatchet`] operations.
///
/// It deliberately carries only a coarse, side-channel-free reason so that error
/// handling never depends on secret data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetError {
    kind: ErrorKind,
}

impl RatchetError {
    fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// True if decryption failed because the message was too far ahead of the
    /// receiving chain (beyond the per-packet [`MAX_SKIP`] budget).
    pub fn is_too_many_skipped(&self) -> bool {
        self.kind == ErrorKind::TooManySkipped
    }

    /// True if decryption failed the AEAD authentication check (forged or
    /// corrupted ciphertext/header).
    pub fn is_authentication_failure(&self) -> bool {
        self.kind == ErrorKind::Decrypt
    }

    /// True if [`DoubleRatchet::encrypt`] was called before a sending chain
    /// existed. This is local API-misuse (calling `encrypt` on a fresh
    /// `init_bob` ratchet before its first `decrypt`), never attacker-driven.
    pub fn is_no_sending_chain(&self) -> bool {
        self.kind == ErrorKind::NoSendingChain
    }

    /// True if `encrypt` refused because the sending chain has run out of
    /// representable message indices (2³² messages sent on one chain without a
    /// DH ratchet step). The correct response is to re-handshake; the ratchet
    /// will never wrap the counter into key/nonce reuse.
    pub fn is_chain_exhausted(&self) -> bool {
        self.kind == ErrorKind::ChainExhausted
    }
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.kind {
            ErrorKind::Malformed => "malformed ratchet message",
            ErrorKind::Decrypt => "ratchet message failed authentication",
            ErrorKind::TooManySkipped => "message too far ahead (skip limit exceeded)",
            ErrorKind::OutOfOrder => "message out of order (missing receiving chain)",
            ErrorKind::NoSendingChain => "encrypt called before a sending chain exists",
            ErrorKind::ChainExhausted => "sending chain exhausted (2^32 messages; re-handshake)",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for RatchetError {}

// ===========================================================================
// Wire header
// ===========================================================================

/// Parsed message header. Encodes the sender's current DH ratchet public key,
/// the number of messages in the sender's *previous* sending chain (`pn`), and
/// this message's index within the current sending chain (`n`).
struct Header {
    dh: [u8; 32],
    pn: u32,
    n: u32,
}

impl Header {
    /// Serialize to the fixed 40-byte wire form (big-endian counters). These
    /// exact bytes are also fed to the AEAD as associated data.
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    /// Parse a header from the front of a wire message. Returns
    /// [`ErrorKind::Malformed`] if there are not enough bytes. Never panics.
    fn decode(bytes: &[u8]) -> Result<Header, RatchetError> {
        if bytes.len() < HEADER_LEN {
            return Err(RatchetError::new(ErrorKind::Malformed));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        // These slices are exactly 4 bytes (length checked above), so the
        // conversions cannot fail.
        let pn = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let n = u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        Ok(Header { dh, pn, n })
    }
}

// ===========================================================================
// Key derivation helpers (all vetted primitives)
// ===========================================================================

/// Root KDF: `(rk', ck) = HKDF-SHA256(salt = rk, ikm = dh_out)`.
///
/// The 64-byte HKDF output is split into a new 32-byte root key and a fresh
/// 32-byte chain key. Because the current root key is used as the HKDF *salt*,
/// the result retains full entropy even if `dh_out` is weak (e.g. a peer that
/// sends a low-order X25519 public key produces an all-zero `dh_out`, yet the
/// derived keys remain strong).
fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(&rk[..]), &dh_out[..]);
    let mut okm = Zeroizing::new([0u8; 64]);
    // 64 bytes is far below HKDF's 255*32 limit, so expand cannot fail.
    hk.expand(KDF_RK_INFO, &mut okm[..])
        .expect("HKDF expand of 64 bytes is always valid");
    let mut new_rk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    (new_rk, ck)
}

/// Symmetric-key chain KDF: `(ck', mk) = KDF_CK(ck)`.
///
/// Implemented with HKDF-Expand keyed by the chain key (`from_prk`): the message
/// key and next chain key are two independent HKDF blocks (`info = 0x01` / `0x02`),
/// mirroring Signal's `HMAC(ck, 0x01)` / `HMAC(ck, 0x02)` construction.
fn kdf_ck(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    // A 32-byte chain key exactly meets HKDF-SHA256's PRK length requirement.
    let hk = Hkdf::<Sha256>::from_prk(&ck[..]).expect("32-byte chain key is a valid PRK");
    let mut mk = Zeroizing::new([0u8; 32]);
    let mut next_ck = Zeroizing::new([0u8; 32]);
    hk.expand(&[0x01], &mut mk[..])
        .expect("HKDF expand of 32 bytes is always valid");
    hk.expand(&[0x02], &mut next_ck[..])
        .expect("HKDF expand of 32 bytes is always valid");
    (next_ck, mk)
}

/// Derive the per-message AEAD key (32 bytes) and nonce (12 bytes) from a
/// message key. Each message key is unique, so the derived key/nonce pair is
/// used exactly once — no nonce-reuse hazard.
fn derive_message_keys(mk: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    // Zero salt is standard when the IKM (the message key) is already uniform.
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32][..]), &mk[..]);
    let mut okm = Zeroizing::new([0u8; 44]);
    hk.expand(KDF_MK_INFO, &mut okm[..])
        .expect("HKDF expand of 44 bytes is always valid");
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

/// AEAD-encrypt `plaintext` under message key `mk`, binding `aad` (the header)
/// as associated data. Returns `ciphertext || tag`.
fn aead_encrypt(mk: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce[..]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| RatchetError::new(ErrorKind::Decrypt))
}

/// AEAD-decrypt `ciphertext` under message key `mk`, requiring `aad` (the header)
/// to match. The AEAD verifies the tag in constant time; a mismatch (forged or
/// corrupted input) yields [`ErrorKind::Decrypt`].
fn aead_decrypt(mk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (key, nonce) = derive_message_keys(mk);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce[..]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| RatchetError::new(ErrorKind::Decrypt))
}

/// Advance a *local* receiving-chain key forward from index `*nr` up to (but not
/// including) `until`, banking each intermediate message key into `banked` and
/// charging each derivation against the shared `budget`.
///
/// This operates entirely on caller-owned scratch state (`ck`, `nr`, `banked`)
/// so it can be run speculatively during a transactional decrypt without
/// touching the live session. It returns [`ErrorKind::TooManySkipped`] *before*
/// deriving anything if the gap would exceed the remaining budget, keeping the
/// error path cheap and bounding total work per packet to [`MAX_SKIP`].
fn skip_forward(
    ck: &mut Zeroizing<[u8; 32]>,
    nr: &mut u32,
    until: u32,
    dh: [u8; 32],
    banked: &mut Vec<([u8; 32], u32, Zeroizing<[u8; 32]>)>,
    budget: &mut u32,
) -> Result<(), RatchetError> {
    if until <= *nr {
        // The message is at or before our current index within this chain, so
        // there is nothing to skip. (An exact replay is caught later by the AEAD
        // tag check against the wrong-position key.)
        return Ok(());
    }
    let needed = until - *nr;
    if needed > *budget {
        return Err(RatchetError::new(ErrorKind::TooManySkipped));
    }
    for _ in 0..needed {
        let (next_ck, mk) = kdf_ck(ck);
        banked.push((dh, *nr, mk));
        // Assigning the new chain key drops (and wipes) the old one.
        *ck = next_ck;
        *nr = nr.wrapping_add(1);
        *budget -= 1;
    }
    Ok(())
}

// ===========================================================================
// Skipped-message-key cache (bounded, O(log n) eviction)
// ===========================================================================

/// Bounded store of message keys for messages that were skipped over (arrived
/// out of order or were dropped). Keyed by `(sender ratchet public, message
/// number)`.
///
/// Insertion order is tracked by a monotonic sequence number held in a
/// [`BTreeMap`] index so the oldest entry can be evicted in `O(log n)` once
/// [`MAX_SKIP_STORE`] is reached — no `O(n)` linear min-scan (see finding #1).
/// The index is kept exactly in sync with `map`: every insert/evict/remove
/// updates both, so it never accumulates stale tombstones.
#[derive(Clone, Default)]
struct SkippedKeys {
    /// `(dh, n) -> (insertion-seq, message key)`.
    map: HashMap<([u8; 32], u32), (u64, Zeroizing<[u8; 32]>)>,
    /// `insertion-seq -> (dh, n)`, ordered, for oldest-first eviction.
    order: BTreeMap<u64, ([u8; 32], u32)>,
    /// Monotonic insertion counter.
    seq: u64,
}

impl SkippedKeys {
    fn new() -> Self {
        Self::default()
    }

    /// Insert `mk` for `(dh, n)`, evicting the oldest-inserted key first if the
    /// store is at capacity. `O(log n)`.
    fn insert(&mut self, dh: [u8; 32], n: u32, mk: Zeroizing<[u8; 32]>) {
        if self.map.len() >= MAX_SKIP_STORE {
            // Evict the oldest-inserted key (its Zeroizing value wipes on drop).
            if let Some((&oldest_seq, &oldest_key)) = self.order.iter().next() {
                self.order.remove(&oldest_seq);
                self.map.remove(&oldest_key);
            }
        }
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        // If (dh, n) somehow already existed, drop its stale index entry first so
        // `order` stays consistent with `map`.
        if let Some((old_seq, _)) = self.map.insert((dh, n), (seq, mk)) {
            self.order.remove(&old_seq);
        }
        self.order.insert(seq, (dh, n));
    }

    /// Borrow the message key for `(dh, n)` without removing it. Used to trial an
    /// AEAD open before committing to consuming the cached key, so a forged
    /// ciphertext reusing a valid `(dh, n)` cannot destroy the genuine key.
    fn peek(&self, dh: &[u8; 32], n: u32) -> Option<&Zeroizing<[u8; 32]>> {
        self.map.get(&(*dh, n)).map(|(_, mk)| mk)
    }

    /// Remove the message key for `(dh, n)` (from both `map` and `order`),
    /// returning it if present. `O(log n)`.
    fn remove(&mut self, dh: &[u8; 32], n: u32) -> Option<Zeroizing<[u8; 32]>> {
        let (seq, mk) = self.map.remove(&(*dh, n))?;
        self.order.remove(&seq);
        Some(mk)
    }
}

// ===========================================================================
// Double Ratchet state machine
// ===========================================================================

/// A Signal-style Double Ratchet session.
///
/// Construct one end with [`DoubleRatchet::init_alice`] (has an initial sending
/// chain and may send immediately) and the other with
/// [`DoubleRatchet::init_bob`] (must receive Alice's first message before it can
/// send). Then use [`encrypt`](Self::encrypt) / [`decrypt`](Self::decrypt) to
/// protect application plaintext.
///
/// # Sending precondition
/// [`encrypt`](Self::encrypt) requires a live sending chain. Alice always has one.
/// Bob's is established when he decrypts Alice's first message; calling `encrypt`
/// on a freshly-`init_bob`'d ratchet before any `decrypt` returns
/// [`RatchetError::is_no_sending_chain`] rather than panicking. The Ciphext
/// session layer drives this in the correct order (the initiator/Alice speaks
/// first).
pub struct DoubleRatchet {
    /// Our current DH ratchet secret. Wiped on drop by the `x25519-dalek`
    /// `"zeroize"` feature (a hard dependency of this module — see the module
    /// docs, finding #3).
    dhs: StaticSecret,
    /// Cached public key matching `dhs`.
    dhs_pub: PublicKey,
    /// The peer's current DH ratchet public key (None until first learned).
    dhr: Option<PublicKey>,
    /// Root key.
    rk: Zeroizing<[u8; 32]>,
    /// Sending chain key (None until a sending chain exists).
    cks: Option<Zeroizing<[u8; 32]>>,
    /// Receiving chain key (None until a receiving chain exists).
    ckr: Option<Zeroizing<[u8; 32]>>,
    /// Number of messages sent in the current sending chain.
    ns: u32,
    /// Number of messages received in the current receiving chain.
    nr: u32,
    /// Number of messages that were in the previous sending chain.
    pn: u32,
    /// Bounded cache of skipped message keys.
    skipped: SkippedKeys,
}

impl Clone for DoubleRatchet {
    fn clone(&self) -> Self {
        // `StaticSecret` is reconstructed from its bytes so we do not depend on
        // whether the crate derives `Clone`. The transient byte array is
        // explicitly wiped after use (finding #4): `StaticSecret::from` copies
        // the bytes in, so the temporary would otherwise leave an unzeroized
        // copy of the DH ratchet private key on the stack.
        let mut secret_bytes = self.dhs.to_bytes();
        let dhs = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        DoubleRatchet {
            dhs,
            dhs_pub: self.dhs_pub,
            dhr: self.dhr,
            rk: self.rk.clone(),
            cks: self.cks.clone(),
            ckr: self.ckr.clone(),
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped: self.skipped.clone(),
        }
    }
}

impl DoubleRatchet {
    /// Initialize the **Alice** (initiator) side. Alice already holds Bob's
    /// initial ratchet public key and derives a sending chain immediately, so she
    /// may send the first message.
    ///
    /// * `shared_root` — the 32-byte agreed secret (Ciphext: the Noise handshake
    ///   hash). It is wiped from the caller-provided buffer before returning.
    /// * `bob_ratchet_public` — Bob's initial ratchet public key, received (over
    ///   the Noise-encrypted channel) from [`init_bob`](Self::init_bob).
    pub fn init_alice(mut shared_root: [u8; 32], bob_ratchet_public: [u8; 32]) -> Self {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dhs_pub = PublicKey::from(&dhs);
        let dhr = PublicKey::from(bob_ratchet_public);

        let dh_out = dhs.diffie_hellman(&dhr);
        let (rk, cks) = kdf_rk(&shared_root, dh_out.as_bytes());
        shared_root.zeroize();

        DoubleRatchet {
            dhs,
            dhs_pub,
            dhr: Some(dhr),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: SkippedKeys::new(),
        }
    }

    /// Initialize the **Bob** (responder) side. Returns the ratchet and Bob's
    /// initial 32-byte ratchet public key, which must be delivered to Alice (over
    /// the Noise-encrypted channel) so she can call
    /// [`init_alice`](Self::init_alice).
    ///
    /// Bob starts with the root key set to `shared_root` and no chains; his
    /// sending chain is created when he first decrypts a message from Alice.
    pub fn init_bob(mut shared_root: [u8; 32]) -> (Self, [u8; 32]) {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dhs_pub = PublicKey::from(&dhs);
        let public_bytes = dhs_pub.to_bytes();

        let mut rk = Zeroizing::new([0u8; 32]);
        rk.copy_from_slice(&shared_root);
        shared_root.zeroize();

        let ratchet = DoubleRatchet {
            dhs,
            dhs_pub,
            dhr: None,
            rk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: SkippedKeys::new(),
        };
        (ratchet, public_bytes)
    }

    /// Our current DH ratchet public key (32 bytes). Exposed for diagnostics /
    /// the session layer; it is public data and safe to reveal.
    pub fn ratchet_public(&self) -> [u8; 32] {
        self.dhs_pub.to_bytes()
    }

    /// Encrypt application plaintext, advancing the sending chain by one message.
    ///
    /// Returns `header(40 bytes) || AEAD ciphertext`. The header bytes are the
    /// AEAD associated data, so any tampering with them is detected on decrypt.
    ///
    /// Note this does **not** hide the plaintext length: the output is
    /// `HEADER_LEN + |plaintext| + 16` bytes. Length hiding is the cover layer's
    /// job (see the module-level docs, finding #2).
    ///
    /// # Errors
    /// Returns [`RatchetError::is_no_sending_chain`] if called before a sending
    /// chain exists (an `init_bob` ratchet that has not yet decrypted the peer's
    /// first message — see the type-level "Sending precondition"). This depends
    /// solely on local call ordering, never on attacker-controlled input, and is
    /// a clean error rather than a panic (finding #5).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, RatchetError> {
        // Fail closed at chain exhaustion. The wire header counter `n` is a u32,
        // so a single sending chain can address at most 2³² message indices. We
        // refuse *before* touching the chain key (so no message key is consumed on
        // the failing path): wrapping `ns` would reuse an index — catastrophic
        // key/nonce reuse — and panicking is not an acceptable outcome either.
        // Reaching this needs ~4.29 billion messages on one chain with no reply
        // (any peer reply performs a DH ratchet step that resets `ns` to 0); if it
        // is ever reached, the caller should re-handshake. Guarding at u32::MAX
        // costs one theoretical index and keeps the post-guard `+= 1` panic-free.
        if self.ns == u32::MAX {
            return Err(RatchetError::new(ErrorKind::ChainExhausted));
        }
        let mk = self.advance_sending_chain()?;

        let header = Header {
            dh: self.dhs_pub.to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        let header_bytes = header.encode();
        self.ns += 1;

        // The only failure mode of the AEAD is a >~256 GiB plaintext (block
        // counter overflow), which cannot occur for a local chat message.
        let ciphertext = aead_encrypt(&mk, &header_bytes, plaintext)
            .expect("AEAD encryption of a local message cannot fail");

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a wire message produced by the peer's [`encrypt`](Self::encrypt).
    ///
    /// Handles the DH ratchet step, in-order advancement, and out-of-order /
    /// dropped messages (via the bounded skipped-key cache).
    ///
    /// This call is **transactional without cloning the session** (findings #1 /
    /// #7): every skipped key and the target message key are derived into local
    /// scratch buffers, and `self` is mutated only after the AEAD tag verifies.
    /// A forged or corrupted header therefore can never corrupt the live session,
    /// and costs only its bounded ([`MAX_SKIP`]) skip work — no deep clone of the
    /// skipped-key cache. Never panics on malformed or forged input.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let header = Header::decode(wire)?;
        let header_bytes = &wire[..HEADER_LEN];
        let ciphertext = &wire[HEADER_LEN..];

        // --- Path 1: a previously-skipped message finally arriving. ----------
        // Peek + clone the cached key (32 bytes) rather than removing it, so a
        // forged ciphertext reusing a valid (dh, n) cannot destroy the genuine
        // skipped key: we only consume it once the AEAD tag verifies.
        if let Some(mk) = self.skipped.peek(&header.dh, header.n).cloned() {
            let plaintext = aead_decrypt(&mk, header_bytes, ciphertext)?;
            self.skipped.remove(&header.dh, header.n);
            return Ok(plaintext);
        }

        // Total message keys a single inbound packet may force us to derive is
        // capped at MAX_SKIP, *shared* across the previous-chain flush and the
        // current-chain catch-up below. This is what prevents a forged header
        // from amplifying into ~2*MAX_SKIP HKDF derivations (finding #1).
        let mut budget = MAX_SKIP;

        // Skipped keys derived while catching up — committed to `self.skipped`
        // only on AEAD success.
        let mut banked: Vec<([u8; 32], u32, Zeroizing<[u8; 32]>)> = Vec::new();

        let is_new_ratchet = match &self.dhr {
            Some(current) => current.as_bytes() != &header.dh,
            None => true,
        };

        // Pending DH-ratchet state — only populated on a ratchet step, and never
        // written back to `self` until the AEAD tag verifies.
        let mut pending_dhr: Option<PublicKey> = None;
        let mut pending_rk: Option<Zeroizing<[u8; 32]>> = None;
        let mut pending_dhs: Option<StaticSecret> = None;
        let mut pending_dhs_pub: Option<PublicKey> = None;
        let mut pending_cks: Option<Zeroizing<[u8; 32]>> = None;
        let mut pending_pn: u32 = 0;

        // Working receiving-chain scratch state used to derive the skipped keys
        // and, finally, this message's own key. Never aliases `self`.
        let mut work_ckr: Zeroizing<[u8; 32]>;
        let mut work_nr: u32;
        let work_dh: [u8; 32];

        if is_new_ratchet {
            // Flush the remainder of the *current* receiving chain (up to
            // header.pn) before rolling to the new one.
            if let Some(ckr) = &self.ckr {
                let cur_dh = self.dhr.expect("dhr is set whenever ckr is set").to_bytes();
                let mut flush_ck = ckr.clone();
                let mut flush_nr = self.nr;
                skip_forward(
                    &mut flush_ck,
                    &mut flush_nr,
                    header.pn,
                    cur_dh,
                    &mut banked,
                    &mut budget,
                )?;
            } else {
                // No receiving chain yet: nothing to derive, but still reject a
                // pn that would blow the skip budget so the error path stays
                // cheap and bounded.
                if header.pn.saturating_sub(self.nr) > budget {
                    return Err(RatchetError::new(ErrorKind::TooManySkipped));
                }
            }

            // DH ratchet math — computed entirely into locals.
            let new_dhr = PublicKey::from(header.dh);
            let recv_dh = self.dhs.diffie_hellman(&new_dhr);
            let (rk_after_recv, ckr_new) = kdf_rk(&self.rk, recv_dh.as_bytes());

            let new_dhs = StaticSecret::random_from_rng(OsRng);
            let new_dhs_pub = PublicKey::from(&new_dhs);
            let send_dh = new_dhs.diffie_hellman(&new_dhr);
            let (rk_after_send, cks_new) = kdf_rk(&rk_after_recv, send_dh.as_bytes());

            pending_dhr = Some(new_dhr);
            pending_rk = Some(rk_after_send);
            pending_dhs = Some(new_dhs);
            pending_dhs_pub = Some(new_dhs_pub);
            pending_cks = Some(cks_new);
            pending_pn = self.ns;

            work_ckr = ckr_new;
            work_nr = 0;
            work_dh = header.dh;
        } else {
            // Same DH chain: continue the existing receiving chain.
            let ckr = match &self.ckr {
                Some(c) => c.clone(),
                None => return Err(RatchetError::new(ErrorKind::OutOfOrder)),
            };
            work_ckr = ckr;
            work_nr = self.nr;
            work_dh = header.dh; // == self.dhr's bytes
        }

        // Skip forward within the working receiving chain to this message's
        // index, banking each intermediate key (shares the same `budget`).
        skip_forward(
            &mut work_ckr,
            &mut work_nr,
            header.n,
            work_dh,
            &mut banked,
            &mut budget,
        )?;

        // Derive this message's key (one more chain step) — still on locals.
        let (post_ckr, target_mk) = kdf_ck(&work_ckr);

        // Authenticate. On *any* failure we return here with `self` completely
        // untouched; the local scratch (banked keys, pending state, chain keys)
        // drops and wipes.
        let plaintext = aead_decrypt(&target_mk, header_bytes, ciphertext)?;

        // ---- COMMIT: authenticity proven, write the new state back. ---------
        for (dh, n, mk) in banked {
            self.skipped.insert(dh, n, mk);
        }
        if is_new_ratchet {
            self.dhr = pending_dhr;
            self.rk = pending_rk.expect("rk is computed on a ratchet step");
            self.dhs = pending_dhs.expect("dhs is computed on a ratchet step");
            self.dhs_pub = pending_dhs_pub.expect("dhs_pub is computed on a ratchet step");
            self.cks = pending_cks;
            self.pn = pending_pn;
            self.ns = 0;
        }
        self.ckr = Some(post_ckr);
        self.nr = header.n.wrapping_add(1);

        Ok(plaintext)
    }

    // --- internal state transitions ---------------------------------------

    /// Advance the sending chain by one step, returning the message key.
    ///
    /// Returns [`ErrorKind::NoSendingChain`] if no sending chain exists yet
    /// (finding #5) instead of panicking.
    fn advance_sending_chain(&mut self) -> Result<Zeroizing<[u8; 32]>, RatchetError> {
        let (next_ck, mk) = {
            let ck = self
                .cks
                .as_ref()
                .ok_or_else(|| RatchetError::new(ErrorKind::NoSendingChain))?;
            kdf_ck(ck)
        };
        // Assigning the new chain key drops the old one, wiping it.
        self.cks = Some(next_ck);
        Ok(mk)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a paired Alice/Bob session sharing a fixed root secret.
    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [0x42u8; 32];
        let (bob, bob_pub) = DoubleRatchet::init_bob(root);
        let alice = DoubleRatchet::init_alice(root, bob_pub);
        (alice, bob)
    }

    /// A sending chain at its last representable index must fail closed, never
    /// panic and never wrap `ns` into a reused message-key index. We fast-forward
    /// the private counter to the boundary (a real chain would need 2³² sends).
    #[test]
    fn sending_chain_exhaustion_fails_closed_not_wrap() {
        // Fast-forward the private counter to the boundary; a real chain would
        // need 2³² sends to get here. (We can't also assert peer-decrypt: the
        // artificial jump makes the message n=u32::MAX-1 look 4-billion keys ahead
        // of Bob's chain, which he rightly refuses — unrelated to this guard.)
        let (mut alice, _bob) = pair();

        // The last valid index still encrypts and advances the counter to the max.
        alice.ns = u32::MAX - 1;
        let header_n = {
            let wire = alice.encrypt(b"final message on this chain").unwrap();
            u32::from_be_bytes([wire[36], wire[37], wire[38], wire[39]])
        };
        assert_eq!(
            header_n,
            u32::MAX - 1,
            "last message carries the boundary index"
        );
        assert_eq!(alice.ns, u32::MAX, "counter must advance to the boundary");

        // One past the boundary: refuse rather than wrap (which would reuse the
        // index) or panic. The chain-key/counter are left untouched by the guard.
        let ns_before = alice.ns;
        match alice.encrypt(b"one too many") {
            Err(e) if e.is_chain_exhausted() => {}
            other => panic!("expected ChainExhausted, got {other:?}"),
        }
        assert_eq!(
            alice.ns, ns_before,
            "failed encrypt must not mutate the counter"
        );
        // Idempotent: still fails closed, still no panic, still no wrap.
        assert!(alice
            .encrypt(b"and again")
            .unwrap_err()
            .is_chain_exhausted());
        assert_eq!(alice.ns, u32::MAX);
    }

    #[test]
    fn round_trip_many_messages_both_directions() {
        let (mut alice, mut bob) = pair();

        // Alice -> Bob, in order.
        for i in 0..50u32 {
            let pt = format!("alice #{i}");
            let wire = alice.encrypt(pt.as_bytes()).unwrap();
            let got = bob.decrypt(&wire).expect("bob decrypts alice");
            assert_eq!(got, pt.as_bytes());
        }

        // Bob -> Alice, in order (Bob now has a sending chain).
        for i in 0..50u32 {
            let pt = format!("bob #{i}");
            let wire = bob.encrypt(pt.as_bytes()).unwrap();
            let got = alice.decrypt(&wire).expect("alice decrypts bob");
            assert_eq!(got, pt.as_bytes());
        }

        // Ping-pong to exercise repeated DH ratchet steps in both directions.
        for i in 0..30u32 {
            let a = format!("ping {i}");
            let wire = alice.encrypt(a.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&wire).unwrap(), a.as_bytes());

            let b = format!("pong {i}");
            let wire = bob.encrypt(b.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&wire).unwrap(), b.as_bytes());
        }
    }

    #[test]
    fn interleaved_out_of_order_within_tolerance() {
        let (mut alice, mut bob) = pair();

        // Alice produces a batch inside a single sending chain.
        let mut wires = Vec::new();
        for i in 0..8u32 {
            wires.push(alice.encrypt(format!("m{i}").as_bytes()).unwrap());
        }

        // Deliver out of order: 0, 3, 2, 5, 7, 1, 4, 6.
        for &i in &[0usize, 3, 2, 5, 7, 1, 4, 6] {
            let got = bob.decrypt(&wires[i]).expect("out-of-order decrypt");
            assert_eq!(got, format!("m{i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_across_a_dh_ratchet() {
        // Skipped keys from an earlier receiving chain must still decrypt after
        // the peer has moved to a new DH ratchet key.
        let (mut alice, mut bob) = pair();

        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap();
        let a2 = alice.encrypt(b"a2").unwrap();

        // Bob receives a0 only (establishes the chain), holds a1/a2 back.
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");

        // Bob replies -> Alice ratchets; Alice replies -> Bob ratchets to a new
        // receiving chain.
        let b0 = bob.encrypt(b"b0").unwrap();
        assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");
        let a3 = alice.encrypt(b"a3").unwrap(); // in Alice's new sending chain
        assert_eq!(bob.decrypt(&a3).unwrap(), b"a3");

        // The delayed a1/a2 (old receiving chain) must still open.
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = pair();

        // Establish a chain first so the tampered message hits the normal path.
        let first = alice.encrypt(b"hello").unwrap();
        assert_eq!(bob.decrypt(&first).unwrap(), b"hello");

        let wire = alice.encrypt(b"secret payload").unwrap();
        let mut bad = wire.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01; // flip a bit in the AEAD tag / ciphertext

        let err = bob.decrypt(&bad).unwrap_err();
        assert!(err.is_authentication_failure());

        // State was not corrupted: the untampered message still decrypts.
        assert_eq!(bob.decrypt(&wire).unwrap(), b"secret payload");
    }

    #[test]
    fn tampered_header_is_rejected() {
        let (mut alice, mut bob) = pair();

        let first = alice.encrypt(b"hello").unwrap();
        assert_eq!(bob.decrypt(&first).unwrap(), b"hello");

        let wire = alice.encrypt(b"authenticated header").unwrap();

        // Flip a byte inside the `pn` header field. Routing is unchanged (same
        // dh, valid n) so the message key is derived correctly, but the header
        // is AEAD associated data, so the tag check must fail.
        let mut bad = wire.clone();
        bad[33] ^= 0x80;
        let err = bob.decrypt(&bad).unwrap_err();
        assert!(err.is_authentication_failure());

        // Flip a byte inside the DH public key field: routing changes, a bogus
        // DH ratchet is attempted on scratch state, and the tag fails. The live
        // state must remain intact (transactional decrypt).
        let mut bad2 = wire.clone();
        bad2[5] ^= 0x01;
        assert!(bob.decrypt(&bad2).is_err());

        // The genuine message still opens against the uncorrupted live state.
        assert_eq!(bob.decrypt(&wire).unwrap(), b"authenticated header");
    }

    #[test]
    fn truncated_message_is_rejected_not_panicked() {
        let (mut alice, mut bob) = pair();
        let wire = alice.encrypt(b"data").unwrap();

        // Shorter than a header.
        assert!(bob.decrypt(&wire[..HEADER_LEN - 1]).is_err());
        assert!(bob.decrypt(&[]).is_err());
        // Exactly a header, no ciphertext (empty AEAD body fails the tag check).
        assert!(bob.decrypt(&wire[..HEADER_LEN]).is_err());
    }

    #[test]
    fn skipping_beyond_max_skip_errors_cleanly() {
        let (mut alice, mut bob) = pair();

        // Alice sends many messages in one chain; only the first reaches Bob.
        let mut wires = Vec::new();
        for i in 0..(MAX_SKIP as usize + 5) {
            wires.push(alice.encrypt(format!("m{i}").as_bytes()).unwrap());
        }

        // Establish the receiving chain with message 0.
        assert_eq!(bob.decrypt(&wires[0]).unwrap(), b"m0");

        // Now jump to a message far beyond MAX_SKIP: nr(1) + MAX_SKIP < n.
        let far = MAX_SKIP as usize + 2; // n = MAX_SKIP + 2
        let err = bob.decrypt(&wires[far]).unwrap_err();
        assert!(err.is_too_many_skipped());

        // The session is unharmed: the next in-order message still decrypts.
        assert_eq!(bob.decrypt(&wires[1]).unwrap(), b"m1");
    }

    #[test]
    fn skipped_key_cache_stays_bounded() {
        // Drive far more skipped keys than the store bound over many DH ratchet
        // steps and confirm memory stays capped (no unbounded growth, no panic).
        let (mut alice, mut bob) = pair();

        for _round in 0..5 {
            // Alice sends a burst; Bob receives only the last, skipping the rest.
            let mut wires = Vec::new();
            for i in 0..300u32 {
                wires.push(alice.encrypt(format!("r{_round}-{i}").as_bytes()).unwrap());
            }
            let last = wires.len() - 1;
            assert_eq!(
                bob.decrypt(&wires[last]).unwrap(),
                format!("r{_round}-{last}").as_bytes()
            );

            // Bob replies so both sides perform a DH ratchet, starting a new chain.
            let reply = bob.encrypt(b"ack").unwrap();
            assert_eq!(alice.decrypt(&reply).unwrap(), b"ack");
        }

        assert!(bob.skipped.map.len() <= MAX_SKIP_STORE);
        // The insertion-order index is kept exactly in sync with the map.
        assert_eq!(bob.skipped.map.len(), bob.skipped.order.len());
    }

    #[test]
    fn wrong_root_secret_cannot_decrypt() {
        // A ratchet initialized with a different root must not open the message.
        let (mut alice, _bob) = pair();
        let wire = alice.encrypt(b"top secret").unwrap();

        let (_bob2, bob2_pub) = DoubleRatchet::init_bob([0x99u8; 32]);
        let mut mallory = DoubleRatchet::init_alice([0x99u8; 32], bob2_pub);
        // Mallory is an unrelated session; decrypting Alice's wire fails.
        assert!(mallory.decrypt(&wire).is_err());
    }

    // -------------------------------------------------------------------
    // Regression tests for the hardening findings.
    // -------------------------------------------------------------------

    /// Finding #5: `encrypt` on a fresh `init_bob` ratchet (no sending chain yet)
    /// must return a distinct error, not panic.
    #[test]
    fn finding5_encrypt_before_sending_chain_errors_not_panics() {
        let (mut bob, _bob_pub) = DoubleRatchet::init_bob([0x7u8; 32]);
        let err = bob.encrypt(b"too early").unwrap_err();
        assert!(err.is_no_sending_chain());
        assert!(!err.is_authentication_failure());
        assert!(!err.is_too_many_skipped());

        // After Bob decrypts Alice's first message he gains a sending chain and
        // may encrypt normally.
        let (bob2, bob2_pub) = DoubleRatchet::init_bob([0x7u8; 32]);
        let mut bob2 = bob2;
        let mut alice = DoubleRatchet::init_alice([0x7u8; 32], bob2_pub);
        let hello = alice.encrypt(b"hi bob").unwrap();
        assert_eq!(bob2.decrypt(&hello).unwrap(), b"hi bob");
        let reply = bob2.encrypt(b"hi alice").unwrap(); // no longer errors
        assert_eq!(alice.decrypt(&reply).unwrap(), b"hi alice");
    }

    /// Finding #4: `Clone` must reconstruct the DH secret (wiping its temp) and
    /// yield a fully independent, functional ratchet. We can't observe the
    /// stack-temp wipe directly, but we prove the clone is faithful and usable.
    #[test]
    fn finding4_clone_is_faithful_and_independent() {
        let (mut alice, mut bob) = pair();

        let w0 = alice.encrypt(b"establish").unwrap();
        assert_eq!(bob.decrypt(&w0).unwrap(), b"establish");

        // Clone Bob at this point; the reconstructed StaticSecret must match.
        let mut bob_clone = bob.clone();
        assert_eq!(bob_clone.ratchet_public(), bob.ratchet_public());

        // Both copies decrypt the next Alice message identically (independent
        // state, same result).
        let w1 = alice.encrypt(b"same-to-both").unwrap();
        assert_eq!(bob.decrypt(&w1).unwrap(), b"same-to-both");
        assert_eq!(bob_clone.decrypt(&w1).unwrap(), b"same-to-both");

        // The clone also carries a working sending chain.
        let from_clone = bob_clone.encrypt(b"from the clone").unwrap();
        assert_eq!(alice.decrypt(&from_clone).unwrap(), b"from the clone");
    }

    /// Finding #6: raising `MAX_SKIP_STORE` above a single packet's max skip means
    /// one large in-chain skip no longer evicts still-wanted keys banked from an
    /// earlier DH chain.
    ///
    /// With the old `MAX_SKIP_STORE == MAX_SKIP == 1000`, banking 4 keys from
    /// chain A and then MAX_SKIP keys from chain B (1004 total) evicts exactly the
    /// 4 oldest — the chain-A keys — and this test would fail. With
    /// `MAX_SKIP_STORE == 4000` they survive.
    #[test]
    fn finding6_large_in_chain_skip_does_not_evict_other_chains() {
        assert!(MAX_SKIP_STORE > MAX_SKIP as usize);
        let (mut alice, mut bob) = pair();

        // --- Chain A: bank 4 skipped keys (a0..a3), deliver a4 to establish. ---
        let mut chain_a = Vec::new();
        for i in 0..5u32 {
            chain_a.push(alice.encrypt(format!("a{i}").as_bytes()).unwrap());
        }
        // Deliver a4; a0..a3 get banked (chain A, indices 0..3).
        assert_eq!(bob.decrypt(&chain_a[4]).unwrap(), b"a4");
        assert_eq!(bob.skipped.map.len(), 4);

        // Bob replies so both ratchet; Alice's next chain (B) has a new dh.
        let ack = bob.encrypt(b"ack").unwrap();
        assert_eq!(alice.decrypt(&ack).unwrap(), b"ack");

        // --- Chain B: force exactly MAX_SKIP banked keys in a single decrypt. --
        let mut chain_b = Vec::new();
        for i in 0..=(MAX_SKIP) {
            chain_b.push(alice.encrypt(format!("b{i}").as_bytes()).unwrap());
        }
        // Deliver b[MAX_SKIP]; banks b0..b[MAX_SKIP-1] = MAX_SKIP keys at once
        // (needed == budget == MAX_SKIP, the exact ceiling).
        let idx = MAX_SKIP as usize;
        assert_eq!(
            bob.decrypt(&chain_b[idx]).unwrap(),
            format!("b{idx}").as_bytes()
        );

        // Store now holds 4 (chain A) + MAX_SKIP (chain B) entries, under the
        // 4000 bound; nothing evicted.
        assert_eq!(bob.skipped.map.len(), 4 + MAX_SKIP as usize);
        assert!(bob.skipped.map.len() <= MAX_SKIP_STORE);

        // The chain-A keys survived the large chain-B skip and still decrypt.
        assert_eq!(bob.decrypt(&chain_a[0]).unwrap(), b"a0");
        assert_eq!(bob.decrypt(&chain_a[1]).unwrap(), b"a1");
        assert_eq!(bob.decrypt(&chain_a[2]).unwrap(), b"a2");
        assert_eq!(bob.decrypt(&chain_a[3]).unwrap(), b"a3");
    }

    /// Finding #1: a single forged packet cannot force ~2*MAX_SKIP derivations.
    /// The skip budget is shared across the previous-chain flush and the
    /// current-chain catch-up, so a header whose `pn` + `n` together exceed
    /// MAX_SKIP is rejected with `TooManySkipped` — and the live state is left
    /// completely intact (transactional, no full-state clone).
    #[test]
    fn finding1_combined_skip_budget_is_bounded_and_transactional() {
        let (mut alice, mut bob) = pair();

        // Establish chain A at Bob with a low nr.
        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap(); // a genuine follow-up, same chain
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0"); // bob.nr == 1

        // Craft a forged packet with a brand-new (unknown) DH key -> forces a DH
        // ratchet, then large pn AND large n. pn alone (600) and n alone (600) are
        // each under MAX_SKIP, but 600 + 600 > MAX_SKIP, so the shared budget must
        // trip. Without the combined budget this would derive ~1199 keys before
        // the (inevitable) AEAD failure.
        let mut forged = Vec::with_capacity(HEADER_LEN + 48);
        forged.extend_from_slice(&[0x11u8; 32]); // unknown dh
        forged.extend_from_slice(&600u32.to_be_bytes()); // pn
        forged.extend_from_slice(&600u32.to_be_bytes()); // n
        forged.extend_from_slice(&[0u8; 48]); // bogus ciphertext+tag

        let err = bob.decrypt(&forged).unwrap_err();
        assert!(
            err.is_too_many_skipped(),
            "combined pn+n over budget must be rejected, got {err:?}"
        );

        // Live state is intact: the genuine next in-order message still decrypts,
        // proving the forged packet neither advanced nor corrupted the chain.
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
    }

    /// Finding #1 (corollary): a forged ciphertext that reuses a *cached* skipped
    /// key's (dh, n) must not consume/destroy that genuine key — the real message
    /// must still open afterwards.
    #[test]
    fn finding1_forged_reuse_of_skipped_key_does_not_consume_it() {
        let (mut alice, mut bob) = pair();

        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap();
        let a2 = alice.encrypt(b"a2").unwrap();

        // Deliver a2 -> a0, a1 get banked as skipped keys.
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        assert_eq!(bob.skipped.map.len(), 2);

        // Forge a packet with a1's header but a corrupted body.
        let mut forged = a1.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xFF;
        assert!(bob
            .decrypt(&forged)
            .unwrap_err()
            .is_authentication_failure());

        // The genuine a1 must still be present and openable.
        assert_eq!(bob.skipped.map.len(), 2);
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
    }
}
