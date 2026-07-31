//! Sender-Keys group encryption for Ciphext.
//!
//! This is the WhatsApp/Signal "sender key" design for efficient group
//! messaging. Every member owns a single [`SenderKeyState`] (a symmetric hash
//! ratchet plus an Ed25519 signing key). A member distributes the *public*
//! half of that state — a [`SenderKeyDistribution`] — to every other member
//! once, out of band, over the existing pairwise Noise channels (that transport
//! is **not** this module's concern; `distribution()`/`encode()` just produce
//! the bytes you hand to the pairwise layer to encrypt and send).
//!
//! To send to the group a member encrypts **once** with their own sender key,
//! ratcheting it forward per message, and signs the result. Every recipient
//! holds a [`ReceiverState`] built from that member's distribution, verifies the
//! signature, ratchets their copy of the chain up to the message's iteration,
//! and decrypts.
//!
//! # Why the signature matters
//!
//! The chain key is *symmetric*: every recipient holds a copy of the sending
//! member's chain key, so any recipient could forge a ciphertext that decrypts
//! cleanly. The per-message Ed25519 signature over `iteration || ciphertext` is
//! what binds a message to its actual author and stops one group member from
//! impersonating another. Verification therefore happens **first**, before any
//! chain advancement or decryption, and a forged or altered message is rejected
//! without mutating receiver state.
//!
//! # Security properties enforced here
//!
//! * Signature is verified before any state change or key derivation.
//! * Each iteration yields a unique message key **and** nonce from the chain
//!   KDF; the iteration is bound into the AEAD associated data. No key or
//!   (key, nonce) pair is ever reused.
//! * Bounded work: at most [`MAX_SKIP`] chain steps per `decrypt`, and a
//!   globally bounded skipped-key store. No unbounded loops or memory.
//! * No panics on attacker-controlled wire bytes: all framing is length-checked
//!   before indexing and every failure is a typed [`GroupError`].
//! * Chain keys and message keys are wiped via [`zeroize`]; failed/forged
//!   messages never corrupt receiver state (derive into locals, commit on
//!   success).
//!
//! All primitives are vetted crates — HKDF-SHA256 for the ratchet,
//! ChaCha20-Poly1305 for the AEAD, Ed25519 for signatures. Nothing is
//! hand-rolled.

use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Maximum number of chain steps a single `decrypt` may advance (and thus the
/// largest gap between the receiver's current iteration and an incoming
/// message's iteration that will be tolerated). Bounds per-message work.
pub const MAX_SKIP: u32 = 2000;

/// Upper bound on the total number of cached skipped message keys held by a
/// single [`ReceiverState`]. Oldest (lowest-iteration) entries are evicted
/// first when the cache is full. Bounds memory.
const MAX_SKIPPED_STORE: usize = 2000;

/// Length of an Ed25519 signature, in bytes.
const SIG_LEN: usize = 64;

/// Length of a ChaCha20-Poly1305 authentication tag, in bytes. A ciphertext is
/// at least this long (the tag over an empty plaintext).
const TAG_LEN: usize = 16;

/// Length of the big-endian iteration counter on the wire, in bytes.
const ITER_LEN: usize = 4;

/// Smallest possible valid wire message: iteration || (tag-only ciphertext) ||
/// signature.
const MIN_WIRE_LEN: usize = ITER_LEN + TAG_LEN + SIG_LEN;

/// Encoded length of a [`SenderKeyDistribution`]: chain key || iteration ||
/// signing public key.
const DIST_LEN: usize = 32 + ITER_LEN + 32;

/// HKDF `info` label for deriving a one-time message key + nonce from a chain
/// key. Distinct from [`INFO_CHAIN`] so the two outputs are independent.
const INFO_MSG: &[u8] = b"Ciphext-SenderKey-v1-MessageKey";

/// HKDF `info` label for advancing the chain key by one step.
const INFO_CHAIN: &[u8] = b"Ciphext-SenderKey-v1-ChainKey";

/// Errors returned by group decryption. Deliberately coarse so as not to leak
/// which internal check failed beyond what an attacker can already observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupError {
    /// Wire bytes were structurally invalid (bad length / framing).
    Malformed,
    /// The Ed25519 signature did not verify against the sender's key.
    BadSignature,
    /// The AEAD failed to authenticate/decrypt the ciphertext.
    Decrypt,
    /// The message's iteration is more than [`MAX_SKIP`] ahead of the
    /// receiver's current iteration; refused to do unbounded work.
    TooManySkipped,
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            GroupError::Malformed => "malformed group message framing",
            GroupError::BadSignature => "sender signature verification failed",
            GroupError::Decrypt => "AEAD authentication/decryption failed",
            GroupError::TooManySkipped => "message iteration exceeds the skip bound",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for GroupError {}

/// A one-time message key + nonce derived from a chain key at a single
/// iteration. Wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct MessageKeys {
    key: [u8; 32],
    nonce: [u8; 12],
}

/// Derive the one-time message keys for the current chain key and the *next*
/// chain key, in a single HKDF extract with two independent expands.
///
/// The `info` labels differ, so the 44-byte message material and the 32-byte
/// next chain key are cryptographically independent outputs of the same PRK.
fn derive_message_keys(chain_key: &[u8; 32]) -> (MessageKeys, Zeroizing<[u8; 32]>) {
    // `chain_key` is used as IKM with an all-zero salt: HKDF here is a keyed PRF
    // ratchet, not a randomness extractor over low-entropy input.
    let hk = Hkdf::<Sha256>::new(None, chain_key);

    let mut material = Zeroizing::new([0u8; 44]); // 32-byte key || 12-byte nonce
    hk.expand(INFO_MSG, &mut material[..])
        .expect("HKDF expand of 44 bytes is always within length bounds");

    let mut next_chain = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_CHAIN, &mut next_chain[..])
        .expect("HKDF expand of 32 bytes is always within length bounds");

    let mut mk = MessageKeys {
        key: [0u8; 32],
        nonce: [0u8; 12],
    };
    mk.key.copy_from_slice(&material[..32]);
    mk.nonce.copy_from_slice(&material[32..44]);

    (mk, next_chain)
}

/// AEAD-seal `plaintext` under `mk`, binding `aad` (the big-endian iteration).
fn seal(mk: &MessageKeys, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk.key));
    cipher
        .encrypt(
            Nonce::from_slice(&mk.nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Encryption is infallible for a valid 32-byte key and 12-byte nonce at
        // any realistic plaintext length; this cannot be triggered by an
        // attacker (they influence neither the key nor the nonce).
        .expect("ChaCha20-Poly1305 seal cannot fail for a valid key and nonce")
}

/// AEAD-open `ciphertext` under `mk`, checking `aad`. A failure (wrong key,
/// tampered ciphertext, or mismatched associated data) is reported as
/// [`GroupError::Decrypt`].
fn open(mk: &MessageKeys, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, GroupError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk.key));
    cipher
        .decrypt(
            Nonce::from_slice(&mk.nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| GroupError::Decrypt)
}

/// The public half of a member's sending state, handed to every other member so
/// they can decrypt and verify that member.
///
/// This carries the (secret) chain key at some iteration plus the member's
/// Ed25519 **public** key. It MUST be delivered confidentially — encrypt the
/// output of [`SenderKeyDistribution::encode`] with the pairwise Noise channel
/// before sending. The chain-key bytes are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyDistribution {
    chain_key: [u8; 32],
    iteration: u32,
    signing_public: [u8; 32],
}

impl SenderKeyDistribution {
    /// Serialize to `chain_key(32) || iteration(4 BE) || signing_public(32)`.
    ///
    /// The returned bytes contain secret key material (the sender-key chain key),
    /// so the buffer is returned as [`Zeroizing`] and wiped when the caller drops
    /// it — the chain-key bytes never linger in a freed heap allocation. Encrypt
    /// the output for the recipient (pairwise Noise) before transmission.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(DIST_LEN));
        out.extend_from_slice(&self.chain_key);
        out.extend_from_slice(&self.iteration.to_be_bytes());
        out.extend_from_slice(&self.signing_public);
        out
    }

    /// Parse the encoding produced by [`SenderKeyDistribution::encode`].
    ///
    /// Returns [`GroupError::Malformed`] if the length is wrong or the encoded
    /// signing public key is not a valid Ed25519 point.
    pub fn decode(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() != DIST_LEN {
            return Err(GroupError::Malformed);
        }
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&bytes[..32]);

        let iteration = u32::from_be_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| GroupError::Malformed)?,
        );

        let mut signing_public = [0u8; 32];
        signing_public.copy_from_slice(&bytes[36..DIST_LEN]);

        // Reject a public key that is not a valid curve point up front.
        VerifyingKey::from_bytes(&signing_public).map_err(|_| GroupError::Malformed)?;

        Ok(SenderKeyDistribution {
            chain_key,
            iteration,
            signing_public,
        })
    }
}

/// A member's own *sending* state: a symmetric chain key, its iteration, and the
/// member's Ed25519 signing key.
///
/// Advances (ratchets) forward on every [`encrypt`](SenderKeyState::encrypt).
pub struct SenderKeyState {
    chain_key: Zeroizing<[u8; 32]>,
    iteration: u32,
    signing_key: SigningKey,
}

impl SenderKeyState {
    /// Create a fresh sending state: a random 32-byte chain key seeded from the
    /// OS CSPRNG and a fresh Ed25519 keypair.
    pub fn new() -> Self {
        let mut rng = OsRng;
        let mut chain_key = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut chain_key[..]);
        let signing_key = SigningKey::generate(&mut rng);
        SenderKeyState {
            chain_key,
            iteration: 0,
            signing_key,
        }
    }

    /// The current distribution to hand to other members: the current chain key,
    /// its iteration, and this member's Ed25519 **public** key.
    ///
    /// Distribute this once, encrypted, over the pairwise channel. New members
    /// joining later receive whatever the current (already-advanced) state is
    /// and can decrypt from that point forward.
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: *self.chain_key,
            iteration: self.iteration,
            signing_public: self.signing_key.verifying_key().to_bytes(),
        }
    }

    /// Encrypt `plaintext` for the group.
    ///
    /// Derives a one-time message key + nonce from the current chain key, seals
    /// the plaintext with the iteration bound in as associated data, ratchets
    /// the chain forward, then signs `iteration || ciphertext` with the signing
    /// key.
    ///
    /// Wire layout: `iteration(4 BE) || ciphertext || signature(64)`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let iteration = self.iteration;
        let (mk, next_chain) = derive_message_keys(&self.chain_key);
        let aad = iteration.to_be_bytes();
        let ciphertext = seal(&mk, plaintext, &aad);

        // Ratchet forward. Assigning the new chain key drops (and zeroizes) the
        // previous one; `mk` is zeroized when it drops at end of scope.
        self.chain_key = next_chain;
        self.iteration = self.iteration.saturating_add(1);

        // wire = iteration || ciphertext || signature(iteration || ciphertext)
        let mut wire = Vec::with_capacity(ITER_LEN + ciphertext.len() + SIG_LEN);
        wire.extend_from_slice(&aad);
        wire.extend_from_slice(&ciphertext);
        let signature: Signature = self.signing_key.sign(&wire);
        wire.extend_from_slice(&signature.to_bytes());
        wire
    }
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-sender *receiving* state: a copy of that sender's chain key and
/// iteration, that sender's Ed25519 verification key, and a bounded cache of
/// skipped (out-of-order) message keys.
///
/// One of these per remote sender. The group layer maps a sender identity to
/// its `ReceiverState`.
pub struct ReceiverState {
    chain_key: Zeroizing<[u8; 32]>,
    iteration: u32,
    /// `None` if the distribution carried an invalid public key; every
    /// verification then fails as [`GroupError::BadSignature`].
    verify_key: Option<VerifyingKey>,
    /// Iteration -> message key for messages skipped over (delivered out of
    /// order). Bounded by [`MAX_SKIPPED_STORE`]; oldest evicted first.
    skipped: BTreeMap<u32, MessageKeys>,
}

impl ReceiverState {
    /// Build a receiving state from a sender's distribution.
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Self {
        ReceiverState {
            chain_key: Zeroizing::new(dist.chain_key),
            iteration: dist.iteration,
            verify_key: VerifyingKey::from_bytes(&dist.signing_public).ok(),
            skipped: BTreeMap::new(),
        }
    }

    /// Decrypt a wire message produced by the sender's
    /// [`encrypt`](SenderKeyState::encrypt).
    ///
    /// Steps, in order:
    /// 1. Length-check and parse `iteration || ciphertext || signature`.
    /// 2. Verify the Ed25519 signature over `iteration || ciphertext` **first**.
    ///    A bad signature is rejected with no state change.
    /// 3. If the iteration was previously skipped, use the cached key.
    /// 4. Otherwise advance the chain up to the message's iteration (at most
    ///    [`MAX_SKIP`] steps), caching skipped keys, all into locals.
    /// 5. AEAD-open; commit chain advancement and cache updates only on success.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>, GroupError> {
        // --- 1. framing (all bounds checked before indexing) ---
        if wire.len() < MIN_WIRE_LEN {
            return Err(GroupError::Malformed);
        }
        let sig_start = wire.len() - SIG_LEN;
        let signed = &wire[..sig_start]; // iteration || ciphertext
        let ciphertext = &wire[ITER_LEN..sig_start];
        let iteration = u32::from_be_bytes(
            wire[..ITER_LEN]
                .try_into()
                .map_err(|_| GroupError::Malformed)?,
        );
        let sig_bytes: [u8; SIG_LEN] = wire[sig_start..]
            .try_into()
            .map_err(|_| GroupError::Malformed)?;

        // --- 2. verify signature FIRST, before any derivation or state change ---
        let verify_key = self.verify_key.as_ref().ok_or(GroupError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verify_key
            .verify_strict(signed, &signature)
            .map_err(|_| GroupError::BadSignature)?;

        let aad = iteration.to_be_bytes();

        // --- 3. previously skipped (out-of-order) message? ---
        if self.skipped.contains_key(&iteration) {
            // Open with the cached key. On AEAD failure the `?` returns and the
            // cache is left intact (no corruption); on success the key is
            // consumed exactly once.
            let plaintext = {
                let mk = self.skipped.get(&iteration).expect("presence just checked");
                open(mk, ciphertext, &aad)?
            };
            self.skipped.remove(&iteration);
            return Ok(plaintext);
        }

        // --- 4. old/duplicate: already ratcheted past and not cached ---
        if iteration < self.iteration {
            return Err(GroupError::Decrypt);
        }

        // --- 4b. advance up to `iteration`, bounded, into locals only ---
        let gap = iteration - self.iteration;
        if gap > MAX_SKIP {
            return Err(GroupError::TooManySkipped);
        }

        let mut chain = self.chain_key.clone(); // Zeroizing clone
        let mut pending: Vec<(u32, MessageKeys)> = Vec::new();
        let mut index = self.iteration;
        while index < iteration {
            let (mk, next) = derive_message_keys(&chain);
            pending.push((index, mk));
            chain = next;
            index += 1;
        }
        let (target_mk, next_chain) = derive_message_keys(&chain);

        // --- 5. AEAD-open, then commit only on success ---
        // If this fails we return before mutating any receiver state; `pending`,
        // `chain`, `target_mk` are all dropped (and zeroized) here.
        let plaintext = open(&target_mk, ciphertext, &aad)?;

        for (i, mk) in pending {
            self.store_skipped(i, mk);
        }
        self.chain_key = next_chain;
        self.iteration = iteration.saturating_add(1);
        Ok(plaintext)
    }

    /// Insert a skipped message key, evicting the oldest entries if the store is
    /// over capacity. Keeps memory bounded regardless of adversarial gaps.
    fn store_skipped(&mut self, iteration: u32, mk: MessageKeys) {
        self.skipped.insert(iteration, mk);
        while self.skipped.len() > MAX_SKIPPED_STORE {
            let lowest = *self.skipped.keys().next().expect("store is non-empty");
            self.skipped.remove(&lowest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-sign `wire`'s `iteration || ciphertext` prefix with `key` so the
    /// signature is valid again after tampering. Lets a test isolate the AEAD
    /// (`Decrypt`) path from the signature (`BadSignature`) path — the signature
    /// covers the ciphertext, so an untampered attacker flipping a ciphertext
    /// byte would be caught as `BadSignature` first.
    fn resign(wire: &mut [u8], key: &SigningKey) {
        let sig_start = wire.len() - SIG_LEN;
        let sig = key.sign(&wire[..sig_start]);
        wire[sig_start..].copy_from_slice(&sig.to_bytes());
    }

    #[test]
    fn in_order_round_trip() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        for i in 0..50u32 {
            let msg = format!("group message number {i}").into_bytes();
            let wire = sender.encrypt(&msg);
            let got = receiver.decrypt(&wire).expect("in-order decrypt");
            assert_eq!(got, msg);
        }
    }

    #[test]
    fn out_of_order_within_max_skip() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        let msgs: Vec<Vec<u8>> = (0..10u32)
            .map(|i| format!("msg {i}").into_bytes())
            .collect();
        let wires: Vec<Vec<u8>> = msgs.iter().map(|m| sender.encrypt(m)).collect();

        // Interleaved / out-of-order delivery, all within MAX_SKIP.
        let order = [2usize, 0, 1, 5, 3, 4, 9, 6, 8, 7];
        for &i in &order {
            let got = receiver.decrypt(&wires[i]).expect("out-of-order decrypt");
            assert_eq!(got, msgs[i], "message {i}");
        }
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);
        let wire = sender.encrypt(b"");
        assert_eq!(receiver.decrypt(&wire).unwrap(), b"");
    }

    #[test]
    fn flipped_ciphertext_is_rejected_as_decrypt() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        let mut wire = sender.encrypt(b"the quick brown fox");
        // Flip a byte inside the ciphertext region (after the 4-byte iteration,
        // before the 64-byte signature).
        let ct_index = ITER_LEN + 3;
        wire[ct_index] ^= 0x01;
        // Re-sign so the signature is valid over the tampered bytes; this
        // isolates the AEAD failure path from the signature path.
        resign(&mut wire, &sender.signing_key);

        assert_eq!(receiver.decrypt(&wire), Err(GroupError::Decrypt));

        // State was not corrupted: a fresh valid message still decrypts.
        let good = sender.encrypt(b"still working");
        assert_eq!(receiver.decrypt(&good).unwrap(), b"still working");
    }

    #[test]
    fn flipped_signature_is_rejected() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        let mut wire = sender.encrypt(b"hello");
        let last = wire.len() - 1;
        wire[last] ^= 0x01; // flip a signature byte
        assert_eq!(receiver.decrypt(&wire), Err(GroupError::BadSignature));
    }

    #[test]
    fn flipped_iteration_is_rejected() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        let mut wire = sender.encrypt(b"hello");
        wire[0] ^= 0x01; // flip the iteration; signed data no longer matches
        assert_eq!(receiver.decrypt(&wire), Err(GroupError::BadSignature));
    }

    #[test]
    fn message_signed_by_different_key_is_rejected() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        // Valid ciphertext from the real sender's chain, but signed by an
        // attacker who lacks the sender's signing key.
        let mut wire = sender.encrypt(b"impersonation attempt");
        let attacker = SigningKey::generate(&mut OsRng);
        resign(&mut wire, &attacker);

        assert_eq!(receiver.decrypt(&wire), Err(GroupError::BadSignature));
    }

    #[test]
    fn jump_beyond_max_skip_errors_cleanly() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        // Advance the sender far past the receiver: iterations 0..=MAX_SKIP+1.
        let mut last = Vec::new();
        for _ in 0..=(MAX_SKIP + 1) {
            last = sender.encrypt(b"x");
        }
        // The last message's iteration is MAX_SKIP+1, gap MAX_SKIP+1 > MAX_SKIP.
        assert_eq!(receiver.decrypt(&last), Err(GroupError::TooManySkipped));
        // Receiver state untouched: it can still decrypt from iteration 0.
        assert_eq!(receiver.iteration, 0);
    }

    #[test]
    fn exactly_max_skip_is_accepted() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        // Produce messages at iterations 0..=MAX_SKIP; delivering the last one
        // first is a gap of exactly MAX_SKIP, which must be allowed.
        let mut wires = Vec::new();
        for _ in 0..=MAX_SKIP {
            wires.push(sender.encrypt(b"payload"));
        }
        let last = wires.last().unwrap();
        assert_eq!(receiver.decrypt(last).unwrap(), b"payload");
    }

    #[test]
    fn two_independent_senders() {
        let mut alice = SenderKeyState::new();
        let mut bob = SenderKeyState::new();

        // A receiver in the group holds a distribution from each sender.
        let mut from_alice = ReceiverState::from_distribution(&alice.distribution());
        let mut from_bob = ReceiverState::from_distribution(&bob.distribution());

        let a1 = alice.encrypt(b"alice one");
        let b1 = bob.encrypt(b"bob one");
        let a2 = alice.encrypt(b"alice two");
        let b2 = bob.encrypt(b"bob two");

        assert_eq!(from_alice.decrypt(&a1).unwrap(), b"alice one");
        assert_eq!(from_bob.decrypt(&b1).unwrap(), b"bob one");
        assert_eq!(from_bob.decrypt(&b2).unwrap(), b"bob two");
        assert_eq!(from_alice.decrypt(&a2).unwrap(), b"alice two");

        // Cross-wires: Alice's receiver must reject Bob's message (wrong signer).
        assert_eq!(from_alice.decrypt(&b1), Err(GroupError::BadSignature));
    }

    #[test]
    fn distribution_encode_decode_round_trip() {
        let sender = SenderKeyState::new();
        let dist = sender.distribution();
        let bytes = dist.encode();
        assert_eq!(bytes.len(), DIST_LEN);
        let decoded = SenderKeyDistribution::decode(&bytes).expect("valid distribution");

        // A receiver built from the decoded distribution behaves identically to
        // one built from the original: same chain key, iteration, and signer.
        let mut rx = ReceiverState::from_distribution(&decoded);
        let mut sender = sender; // reuse the same signing key & chain state
        let wire = sender.encrypt(b"after decode");
        assert_eq!(rx.decrypt(&wire).unwrap(), b"after decode");
    }

    #[test]
    fn malformed_short_wire_is_rejected() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);
        let _ = sender.encrypt(b"x");
        for len in 0..MIN_WIRE_LEN {
            let junk = vec![0u8; len];
            assert_eq!(receiver.decrypt(&junk), Err(GroupError::Malformed));
        }
    }

    #[test]
    fn replayed_message_after_advance_is_rejected() {
        let mut sender = SenderKeyState::new();
        let dist = sender.distribution();
        let mut receiver = ReceiverState::from_distribution(&dist);

        let w0 = sender.encrypt(b"first");
        let w1 = sender.encrypt(b"second");
        assert_eq!(receiver.decrypt(&w0).unwrap(), b"first");
        assert_eq!(receiver.decrypt(&w1).unwrap(), b"second");
        // Replaying an already-consumed, ratcheted-past message: valid signature
        // but the key is gone. Rejected as Decrypt, no panic.
        assert_eq!(receiver.decrypt(&w0), Err(GroupError::Decrypt));
    }
}
