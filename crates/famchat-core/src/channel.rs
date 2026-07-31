//! The complete sealed message channel — the layer that ties the whole stack
//! together on top of an authenticated [`Established`] connection.
//!
//! A message travels, outbound:
//!
//! ```text
//! Frame  ->  DoubleRatchet::encrypt   (inner, per-message forward secrecy)
//!        ->  cover layer              (packs opaque ratchet ciphertext into
//!                                       FIXED-SIZE cells, constant cadence)
//!        ->  wire::seal (Noise)       (AEAD-seals EACH fixed cell)
//!        ->  constant-size record on the wire
//! ```
//!
//! and inbound is the exact mirror. Sealing each fixed cell with Noise makes the
//! on-wire records constant-size and their DATA/PAD nature invisible — every
//! record is the same size, emitted on a fixed clock, whether or not anyone is
//! typing.
//!
//! [`SealedChannel::establish`] returns a [`SealedSender`] / [`SealedReceiver`]
//! pair so a caller can drive sending and receiving from independent tasks (the
//! send path locks only the ratchet; the receive path owns its own queue).

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Duration;

use crate::cover::{self, CoverConfig, CoverSender};
use crate::message::Frame;
use crate::ratchet::DoubleRatchet;
use crate::session::{Established, SessionInfo};
use crate::wire;

/// Bound on the post-handshake ratchet bootstrap exchange, so a peer that
/// completes the handshake and then withholds its bootstrap record cannot hang
/// us indefinitely (audit finding: the session handshake timeout did not extend
/// to this read).
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);

/// The send half of a sealed channel. Cheap to hold; `send` locks only the
/// ratchet, so it never blocks on the receive path.
pub struct SealedSender {
    ratchet: Arc<Mutex<DoubleRatchet>>,
    outbound: CoverSender,
}

impl SealedSender {
    /// Send an application frame. It is ratcheted, cover-padded into fixed cells,
    /// and Noise-sealed before it reaches the wire.
    pub async fn send(&self, frame: Frame) -> Result<()> {
        let plaintext = frame.encode();
        let ct = {
            let mut r = self.ratchet.lock().await;
            r.encrypt(&plaintext)
                .map_err(|e| anyhow!("encrypt failed: {e}"))?
        };
        self.outbound
            .try_send(ct)
            .map_err(|e| anyhow!("send failed: {e:?}"))
    }
}

/// The receive half of a sealed channel. Owns the background pump tasks, which
/// are aborted when this is dropped.
pub struct SealedReceiver {
    inbound: mpsc::Receiver<Frame>,
    info: SessionInfo,
    tasks: Vec<JoinHandle<()>>,
}

impl SealedReceiver {
    /// Receive the next application frame, or `None` once the channel closes.
    pub async fn recv(&mut self) -> Option<Frame> {
        self.inbound.recv().await
    }

    /// Session metadata (peer fingerprint, transport, trust state).
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }
}

impl Drop for SealedReceiver {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Namespace for establishing a sealed channel over an authenticated connection.
pub struct SealedChannel;

impl SealedChannel {
    /// Establish the full sealed channel using the default cover-traffic cadence.
    pub async fn establish(est: Established) -> Result<(SealedSender, SealedReceiver)> {
        // Default cadence: one 512-byte cell each way every 250ms (~2 KB/s of
        // constant cover traffic per direction, whether or not anyone is typing).
        let cfg = CoverConfig {
            cell_size: cover::CELL_SIZE,
            interval: std::time::Duration::from_millis(250),
        };
        Self::establish_with(est, cfg).await
    }

    /// Establish with an explicit cover-traffic configuration (both peers must
    /// agree on the same `cfg`).
    pub async fn establish_with(
        est: Established,
        cfg: CoverConfig,
    ) -> Result<(SealedSender, SealedReceiver)> {
        let Established {
            mut reader,
            mut writer,
            mut transport,
            handshake_hash,
            is_initiator,
            info,
        } = est;

        // Clamp the cell size so a fixed cover cell plus the Noise AEAD tag always
        // fits one Noise record; an oversized cell_size would otherwise fail to
        // seal and silently kill the send path (audit finding).
        let cfg = {
            let mut c = cfg;
            const MAX_SEALABLE_CELL: usize = 65535 - 3 - 16;
            if c.cell_size > MAX_SEALABLE_CELL {
                c.cell_size = MAX_SEALABLE_CELL;
            }
            c
        };

        // --- Double Ratchet bootstrap over the raw Noise transport (record 0) ---
        // Bounded: a peer that finishes the handshake and then withholds its
        // bootstrap record cannot hang us here.
        let ratchet = tokio::time::timeout(BOOTSTRAP_TIMEOUT, async {
            if is_initiator {
                // Alice: receive Bob's initial ratchet public key, then initialize.
                let mut buf = Vec::new();
                let n = wire::recv_record(&mut reader, &mut buf).await?;
                let bob_pub_bytes = wire::open(&mut transport, &buf[..n])?;
                let bob_pub: [u8; 32] = bob_pub_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("malformed ratchet bootstrap key"))?;
                Ok::<DoubleRatchet, anyhow::Error>(DoubleRatchet::init_alice(
                    handshake_hash,
                    bob_pub,
                ))
            } else {
                // Bob: generate the initial ratchet key, send its public half.
                let (rat, bob_pub) = DoubleRatchet::init_bob(handshake_hash);
                let record = wire::seal(&mut transport, &bob_pub)?;
                wire::send_record(&mut writer, &record).await?;
                Ok(rat)
            }
        })
        .await
        .map_err(|_| anyhow!("ratchet bootstrap timed out"))??;

        let transport = Arc::new(Mutex::new(transport));
        let ratchet = Arc::new(Mutex::new(ratchet));

        // --- Cover channel bridged to the Noise transport via in-memory cell pipes.
        // Cover writes/reads whole fixed cells; each cell becomes one Noise record.
        let cell_total = 3 + cfg.cell_size; // 1 type + 2 length + payload
        let pipe_cap = cell_total * 8;
        let (cover_writer, mut seal_src) = tokio::io::duplex(pipe_cap);
        let (mut open_sink, cover_reader) = tokio::io::duplex(pipe_cap);
        let chan = cover::spawn(cover_reader, cover_writer, cfg);

        // Sealer: read one fixed cell from cover, Noise-seal it, put it on the wire.
        let ts_send = transport.clone();
        let sealer = tokio::spawn(async move {
            let mut cell = vec![0u8; cell_total];
            loop {
                if seal_src.read_exact(&mut cell).await.is_err() {
                    break;
                }
                let record = {
                    let mut t = ts_send.lock().await;
                    wire::seal(&mut t, &cell)
                };
                let record = match record {
                    Ok(r) => r,
                    Err(_) => break,
                };
                if wire::send_record(&mut writer, &record).await.is_err() {
                    break;
                }
            }
        });

        // Opener: receive a Noise record, open it into one fixed cell, feed cover.
        let ts_recv = transport.clone();
        let opener = tokio::spawn(async move {
            let mut buf = Vec::new();
            loop {
                let n = match wire::recv_record(&mut reader, &mut buf).await {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let cell = {
                    let mut t = ts_recv.lock().await;
                    wire::open(&mut t, &buf[..n])
                };
                let cell = match cell {
                    Ok(c) => c,
                    Err(_) => break, // AEAD failure: tampered/desynced — tear down
                };
                if open_sink.write_all(&cell).await.is_err() {
                    break;
                }
            }
        });

        // Inbound frames: drain cover, ratchet-decrypt, decode Frames.
        let (frame_tx, frame_rx) = mpsc::channel::<Frame>(256);
        let rat_recv = ratchet.clone();
        let mut cover_in = chan.inbound;
        let inbound = tokio::spawn(async move {
            while let Some(item) = cover_in.recv().await {
                let ct = match item {
                    Ok(ct) => ct,
                    Err(_) => break, // explicit cover protocol violation
                };
                let plaintext = {
                    let mut r = rat_recv.lock().await;
                    r.decrypt(&ct)
                };
                let plaintext = match plaintext {
                    Ok(p) => p,
                    Err(_) => continue, // forged/undecryptable ratchet frame: drop
                };
                if plaintext.is_empty() {
                    continue; // ratchet "sync" message, not an application frame
                }
                match Frame::decode(&plaintext) {
                    Ok(frame) => {
                        if frame_tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        let outbound = chan.outbound;

        // Alice sends a one-time empty sync so Bob's ratchet gains a sending
        // chain immediately (a responder cannot encrypt until it has decrypted
        // one message).
        if is_initiator {
            let ct = {
                let mut r = ratchet.lock().await;
                r.encrypt(&[])
                    .map_err(|e| anyhow!("ratchet sync failed: {e}"))?
            };
            let _ = outbound.try_send(ct);
        }

        let sender = SealedSender { ratchet, outbound };
        let receiver = SealedReceiver {
            inbound: frame_rx,
            info,
            tasks: vec![sealer, opener, inbound],
        };
        Ok((sender, receiver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Auth, Link};
    use crate::transport::{TcpTransport, Transport};
    use std::time::Duration;

    fn fast_cfg() -> CoverConfig {
        CoverConfig {
            cell_size: crate::cover::CELL_SIZE,
            interval: Duration::from_millis(15),
        }
    }

    /// A message pushed through the ENTIRE production stack — ratchet, cover
    /// cells, and per-cell Noise seal — must arrive intact, both directions.
    #[tokio::test]
    async fn full_stack_round_trip() {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let mut server_link = Link::Listen {
            listener,
            auth: Auth::Code("same-secret-word".into()),
        };

        let t2 = transport.clone();
        let client = tokio::spawn(async move {
            let mut c = Link::Connect {
                transport: t2,
                target: addr,
                auth: Auth::Code("same-secret-word".into()),
            };
            let est = c.establish().await.unwrap();
            let (tx, mut rx) = SealedChannel::establish_with(est, fast_cfg())
                .await
                .unwrap();
            tx.send(Frame::Text("hello from client".into()))
                .await
                .unwrap();
            let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("client recv timed out")
                .expect("client channel closed");
            assert_eq!(got, Frame::Text("hi back from server".into()));
        });

        let est = server_link.establish().await.unwrap();
        let (tx, mut rx) = SealedChannel::establish_with(est, fast_cfg())
            .await
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("server recv timed out")
            .expect("server channel closed");
        assert_eq!(got, Frame::Text("hello from client".into()));
        tx.send(Frame::Text("hi back from server".into()))
            .await
            .unwrap();

        client.await.unwrap();
    }
}
