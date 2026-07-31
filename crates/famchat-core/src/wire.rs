//! Wire protocol: a Noise `XX` handshake followed by length-framed AEAD records.
//!
//! `XX` gives us mutual authentication (both sides prove possession of their
//! static key) and forward secrecy (ephemeral keys per session). After the
//! handshake, every message is sealed with ChaCha20-Poly1305 under keys that
//! never leave the two endpoints. This module is generic over the byte stream,
//! so the exact same handshake runs over a direct TCP socket or a Tor onion
//! stream — the transport is chosen a layer up.

use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use snow::TransportState;
use spake2::{Ed25519Group, Identity as SpakeIdentity, Password, Spake2};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::identity::{Identity, NOISE_PARAMS};

/// Noise messages are capped at 65535 bytes by the spec.
const MAX_NOISE_MSG: usize = 65535;

/// Code-word mode: ephemeral DH (forward secrecy) authenticated by a pre-shared
/// key that only both code-word holders can derive.
const NOISE_PSK_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// Domain separator mixed into the SPAKE2 exchange so a captured transcript
/// can't be replayed against another app.
const SPAKE_APP_ID: &[u8] = b"ciphext/pake/v1";

/// Write a length-prefixed frame (u16 big-endian length + payload).
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_NOISE_MSG {
        return Err(anyhow!("frame too large"));
    }
    w.write_all(&(data.len() as u16).to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame into `buf`, returning its length.
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize> {
    let mut len_bytes = [0u8; 2];
    r.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    buf.resize(len, 0);
    r.read_exact(&mut buf[..len]).await?;
    Ok(len)
}

/// The outcome of a completed handshake.
pub struct Session {
    pub transport: TransportState,
    /// The peer's static public key — hash this for their fingerprint.
    pub remote_static: Vec<u8>,
    /// The Noise handshake hash: a 32-byte value both peers derive identically.
    /// It is secret only in code-word (PSK) mode, where the psk is mixed into the
    /// transcript; in identity (XX) mode it is a hash over public transcript data,
    /// so an eavesdropper can recompute it. It is used ONLY as the Double Ratchet
    /// root *seed* — the real root is HKDF(seed, DH(ratchet keys)), and the ratchet
    /// keys are exchanged inside the encrypted channel — so its secrecy is not
    /// relied upon. Do not use it as a standalone secret or authenticator.
    pub handshake_hash: [u8; 32],
}

/// Snapshot the 32-byte Noise handshake hash (BLAKE2s) before entering transport
/// mode. Both peers compute the same value. This is a transcript-binding value:
/// public in XX mode, secret only in PSK mode — see `Session::handshake_hash`.
fn hs_hash(noise: &snow::HandshakeState) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(&noise.get_handshake_hash()[..32]);
    h
}

/// Run the Noise `XX` handshake as the initiator (the side that connects).
///
/// Message flow:  -> e   |   <- e, ee, s, es   |   -> s, se
pub async fn handshake_initiator<S>(stream: &mut S, id: &Identity) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(id.secret())
        .build_initiator()
        .map_err(|e| anyhow!("handshake init failed: {e}"))?;

    let mut out = vec![0u8; MAX_NOISE_MSG];
    let mut inb = Vec::new();
    let mut scratch = vec![0u8; MAX_NOISE_MSG];

    // -> e
    let n = noise.write_message(&[], &mut out).map_err(hs_err)?;
    write_frame(stream, &out[..n]).await?;

    // <- e, ee, s, es
    let n = read_frame(stream, &mut inb).await?;
    noise
        .read_message(&inb[..n], &mut scratch)
        .map_err(hs_err)?;

    // -> s, se
    let n = noise.write_message(&[], &mut out).map_err(hs_err)?;
    write_frame(stream, &out[..n]).await?;

    finish(noise)
}

/// Run the Noise `XX` handshake as the responder (the side that listens).
pub async fn handshake_responder<S>(stream: &mut S, id: &Identity) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut noise = snow::Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(id.secret())
        .build_responder()
        .map_err(|e| anyhow!("handshake init failed: {e}"))?;

    let mut out = vec![0u8; MAX_NOISE_MSG];
    let mut inb = Vec::new();
    let mut scratch = vec![0u8; MAX_NOISE_MSG];

    // -> e
    let n = read_frame(stream, &mut inb).await?;
    noise
        .read_message(&inb[..n], &mut scratch)
        .map_err(hs_err)?;

    // <- e, ee, s, es
    let n = noise.write_message(&[], &mut out).map_err(hs_err)?;
    write_frame(stream, &out[..n]).await?;

    // -> s, se
    let n = read_frame(stream, &mut inb).await?;
    noise
        .read_message(&inb[..n], &mut scratch)
        .map_err(hs_err)?;

    finish(noise)
}

fn finish(noise: snow::HandshakeState) -> Result<Session> {
    let remote_static = noise
        .get_remote_static()
        .ok_or_else(|| anyhow!("peer did not present a static key"))?
        .to_vec();
    let handshake_hash = hs_hash(&noise);
    let transport = noise
        .into_transport_mode()
        .map_err(|e| anyhow!("failed to enter transport mode: {e}"))?;
    Ok(Session {
        transport,
        remote_static,
        handshake_hash,
    })
}

fn hs_err(e: snow::Error) -> anyhow::Error {
    anyhow!("noise handshake error: {e}")
}

/// Run a symmetric SPAKE2 exchange over the wire and derive a 32-byte key from
/// the shared code word. Both sides must supply the same word; if they don't,
/// they end up with *different* keys and the Noise handshake that follows fails
/// its authentication — which is exactly how a wrong word (or a middleman) is
/// caught. SPAKE2 never puts the word on the wire and resists offline guessing.
async fn derive_psk<S>(stream: &mut S, code: &str, initiator: bool) -> Result<[u8; 32]>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(code.trim().as_bytes()),
        &SpakeIdentity::new(SPAKE_APP_ID),
    );

    // Fixed ordering avoids a deadlock: the initiator writes first, the
    // responder reads first. SPAKE2 messages are independent of each other.
    let mut inbound = Vec::new();
    if initiator {
        write_frame(stream, &outbound).await?;
        read_frame(stream, &mut inbound).await?;
    } else {
        read_frame(stream, &mut inbound).await?;
        write_frame(stream, &outbound).await?;
    }

    let mut shared = state
        .finish(&inbound)
        .map_err(|e| anyhow!("shared-code exchange failed: {e}"))?;

    // CHANNEL BINDING: derive the Noise PSK from the SPAKE2 shared secret via
    // HKDF with an explicit domain-separation label. This 32-byte key is then
    // fed into Noise as the psk0 PSK, so the Noise session key is a function of
    // the PAKE key. A middleman who doesn't know the word cannot derive this
    // key and therefore cannot stand up a Noise session with either party —
    // welding the two protocols so no MITM can slip through the seam between
    // them. (Relaying the SPAKE2 messages gives the two honest endpoints the
    // key but never the relay.)
    let hk = Hkdf::<Sha256>::new(None, &shared);
    let mut psk = [0u8; 32];
    hk.expand(b"ciphext/pake-to-noise-psk/v1", &mut psk)
        .map_err(|_| anyhow!("psk derivation failed"))?;
    shared.zeroize(); // wipe the raw SPAKE2 shared secret; only the PSK survives
    Ok(psk)
}

fn wrong_code_err(e: snow::Error) -> anyhow::Error {
    anyhow!("handshake failed — did both sides enter the same code word? ({e})")
}

/// Code-word handshake, initiator side. No long-term identity is involved;
/// authentication comes entirely from the shared word.
pub async fn handshake_initiator_code<S>(stream: &mut S, code: &str) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut psk = derive_psk(stream, code, true).await?;
    let mut noise = snow::Builder::new(NOISE_PSK_PARAMS.parse()?)
        .psk(0, &psk)
        .build_initiator()
        .map_err(|e| anyhow!("handshake init failed: {e}"))?;
    psk.zeroize(); // the PSK is now mixed into the Noise state; wipe our copy

    let mut out = vec![0u8; MAX_NOISE_MSG];
    let mut inb = Vec::new();
    let mut scratch = vec![0u8; MAX_NOISE_MSG];

    // -> psk, e
    let n = noise.write_message(&[], &mut out).map_err(hs_err)?;
    write_frame(stream, &out[..n]).await?;
    // <- e, ee
    let n = read_frame(stream, &mut inb).await?;
    noise
        .read_message(&inb[..n], &mut scratch)
        .map_err(wrong_code_err)?;

    let handshake_hash = hs_hash(&noise);
    let transport = noise
        .into_transport_mode()
        .map_err(|e| anyhow!("failed to enter transport mode: {e}"))?;
    Ok(Session {
        transport,
        remote_static: Vec::new(),
        handshake_hash,
    })
}

/// Code-word handshake, responder side.
pub async fn handshake_responder_code<S>(stream: &mut S, code: &str) -> Result<Session>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut psk = derive_psk(stream, code, false).await?;
    let mut noise = snow::Builder::new(NOISE_PSK_PARAMS.parse()?)
        .psk(0, &psk)
        .build_responder()
        .map_err(|e| anyhow!("handshake init failed: {e}"))?;
    psk.zeroize(); // the PSK is now mixed into the Noise state; wipe our copy

    let mut out = vec![0u8; MAX_NOISE_MSG];
    let mut inb = Vec::new();
    let mut scratch = vec![0u8; MAX_NOISE_MSG];

    // -> psk, e
    let n = read_frame(stream, &mut inb).await?;
    noise
        .read_message(&inb[..n], &mut scratch)
        .map_err(wrong_code_err)?;
    // <- e, ee
    let n = noise.write_message(&[], &mut out).map_err(hs_err)?;
    write_frame(stream, &out[..n]).await?;

    let handshake_hash = hs_hash(&noise);
    let transport = noise
        .into_transport_mode()
        .map_err(|e| anyhow!("failed to enter transport mode: {e}"))?;
    Ok(Session {
        transport,
        remote_static: Vec::new(),
        handshake_hash,
    })
}

/// Seal a plaintext message into a Noise transport record.
pub fn seal(ts: &mut TransportState, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_NOISE_MSG - 16 {
        return Err(anyhow!("message too long"));
    }
    let mut buf = vec![0u8; plaintext.len() + 16];
    let n = ts
        .write_message(plaintext, &mut buf)
        .map_err(|e| anyhow!("seal failed: {e}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// Open a Noise transport record back into plaintext.
pub fn open(ts: &mut TransportState, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; ciphertext.len()];
    let n = ts
        .read_message(ciphertext, &mut buf)
        .map_err(|e| anyhow!("open failed (tampered or out-of-order record?): {e}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// Send one sealed record over the wire.
pub async fn send_record<W: AsyncWriteExt + Unpin>(w: &mut W, record: &[u8]) -> Result<()> {
    write_frame(w, record).await
}

/// Receive one sealed record from the wire.
pub async fn recv_record<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize> {
    read_frame(r, buf).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tokio::net::{TcpListener, TcpStream};

    fn make_identity() -> Identity {
        let kp = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .unwrap();
        Identity::from_parts(kp.public, kp.private)
    }

    /// Full handshake over loopback: both sides must agree on each other's
    /// static key, and messages must round-trip in both directions.
    #[tokio::test]
    async fn handshake_and_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_id = make_identity();
        let client_id = make_identity();
        let server_pub = server_id.public.clone();
        let client_pub = client_id.public.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut sess = handshake_responder(&mut stream, &server_id).await.unwrap();
            assert_eq!(sess.remote_static, client_pub, "server sees client's key");
            let (mut r, mut w) = stream.into_split();
            let mut buf = Vec::new();
            let n = recv_record(&mut r, &mut buf).await.unwrap();
            let pt = open(&mut sess.transport, &buf[..n]).unwrap();
            assert_eq!(pt, b"hello from client");
            let rec = seal(&mut sess.transport, b"hello from server").unwrap();
            send_record(&mut w, &rec).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut sess = handshake_initiator(&mut stream, &client_id).await.unwrap();
        assert_eq!(sess.remote_static, server_pub, "client sees server's key");
        let (mut r, mut w) = stream.into_split();
        let rec = seal(&mut sess.transport, b"hello from client").unwrap();
        send_record(&mut w, &rec).await.unwrap();
        let mut buf = Vec::new();
        let n = recv_record(&mut r, &mut buf).await.unwrap();
        let pt = open(&mut sess.transport, &buf[..n]).unwrap();
        assert_eq!(pt, b"hello from server");

        server.await.unwrap();
    }

    /// A flipped byte in a sealed record must be rejected by the AEAD.
    #[tokio::test]
    async fn tampered_record_is_rejected() {
        let (a, b) = tokio::io::duplex(4096);
        let mut a = a;
        let mut b = b;
        let server_id = make_identity();
        let client_id = make_identity();

        let (client_sess, server_sess) = tokio::join!(
            async { handshake_initiator(&mut a, &client_id).await.unwrap() },
            async { handshake_responder(&mut b, &server_id).await.unwrap() },
        );
        let mut client_ts = client_sess.transport;
        let mut server_ts = server_sess.transport;

        let mut record = seal(&mut client_ts, b"trust me").unwrap();
        let last = record.len() - 1;
        record[last] ^= 0xFF; // tamper
        assert!(
            open(&mut server_ts, &record).is_err(),
            "tampered record must be rejected"
        );
    }

    /// Matching code words: the PAKE handshake succeeds and messages flow.
    #[tokio::test]
    async fn code_word_match() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let (ca, cb) = tokio::join!(
            handshake_initiator_code(&mut a, "purple-tractor-9"),
            handshake_responder_code(&mut b, "purple-tractor-9"),
        );
        let mut client_ts = ca.expect("initiator handshake").transport;
        let mut server_ts = cb.expect("responder handshake").transport;

        let rec = seal(&mut client_ts, b"it works").unwrap();
        assert_eq!(open(&mut server_ts, &rec).unwrap(), b"it works");
    }

    /// Mismatched code words: the handshake must fail authentication.
    #[tokio::test]
    async fn code_word_mismatch_rejected() {
        use std::time::Duration;
        use tokio::time::timeout;

        let (mut a, mut b) = tokio::io::duplex(8192);
        let (ri, rr) = tokio::join!(
            timeout(
                Duration::from_secs(3),
                handshake_initiator_code(&mut a, "correct-horse")
            ),
            timeout(
                Duration::from_secs(3),
                handshake_responder_code(&mut b, "wrong-horse")
            ),
        );

        let responder_rejected = matches!(rr, Ok(Err(_))) || rr.is_err();
        assert!(
            responder_rejected,
            "responder must reject a mismatched code word"
        );
        let initiator_ok = matches!(ri, Ok(Ok(_)));
        assert!(
            !initiator_ok,
            "initiator must not complete with a mismatched code word"
        );
    }

    /// A multi-chunk file, pushed through the exact production path
    /// (encode -> seal -> open -> decode), must reassemble byte-for-byte.
    #[tokio::test]
    async fn file_frames_survive_transport() {
        use crate::message::{Frame, CHUNK_SIZE};

        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let (ca, cb) = tokio::join!(
            handshake_initiator_code(&mut a, "same-word"),
            handshake_responder_code(&mut b, "same-word"),
        );
        let mut sender = ca.unwrap().transport;
        let mut receiver = cb.unwrap().transport;

        let original: Vec<u8> = (0..(CHUNK_SIZE * 3 + 100))
            .map(|i| (i % 251) as u8)
            .collect();
        let id = [9u8; 16];

        let mut frames = vec![Frame::FileOffer {
            id,
            name: "blob.bin".into(),
            size: original.len() as u64,
        }];
        for c in original.chunks(CHUNK_SIZE) {
            frames.push(Frame::FileChunk {
                id,
                data: c.to_vec(),
            });
        }
        frames.push(Frame::FileEnd { id });

        let mut reassembled = Vec::new();
        let (mut got_offer, mut got_end) = (false, false);
        for f in &frames {
            let record = seal(&mut sender, &f.encode()).unwrap();
            let plaintext = open(&mut receiver, &record).unwrap();
            match Frame::decode(&plaintext).unwrap() {
                Frame::FileOffer { .. } => got_offer = true,
                Frame::FileChunk { data, .. } => reassembled.extend_from_slice(&data),
                Frame::FileEnd { .. } => got_end = true,
                Frame::Text(_)
                | Frame::Group(_)
                | Frame::FileAccept { .. }
                | Frame::FileReject { .. } => {}
            }
        }

        assert!(got_offer && got_end, "offer and end must arrive");
        assert_eq!(reassembled, original, "file must reassemble byte-for-byte");
    }
}
