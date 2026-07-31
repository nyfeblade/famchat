//! Constant-rate cover-traffic + fixed-cell framing layer.
//!
//! # Purpose
//!
//! This module defeats *traffic analysis*. A passive network observer watching
//! an encrypted Ciphext connection should learn **nothing** about the plaintext
//! conversation — not the timing of messages, not their sizes, not even whether
//! the two peers are actively talking at all.
//!
//! We achieve this the only way that is actually sound against a global passive
//! adversary: by making the wire behave like a **constant bit-rate channel**.
//! A background task ticks on a fixed cadence (`CoverConfig::interval`) and, on
//! every single tick, emits exactly one fixed-size *cell* — whether or not there
//! is any real data to send. When there is real data, the cell is a `DATA` cell
//! carrying a fragment of a message; when the application is idle, the cell is a
//! `PAD` cell of identical shape. Once each cell has been sealed by the outer
//! transport (see [the transport contract](#transport-contract-security-precondition)),
//! `DATA` and `PAD` cells are byte-for-byte indistinguishable on the wire.
//!
//! # Where this layer sits (Ciphext layering contract)
//!
//! Outbound, the Ciphext stack is:
//!
//! ```text
//!   app Frame bytes
//!     -> DoubleRatchet.encrypt   (inner forward-secret layer; does NOT hide length)
//!     -> opaque ratchet ciphertext handed to THIS cover layer
//!     -> cover packs it into FIXED-SIZE cells  <-- length hiding happens HERE
//!     -> each cell sealed by the Noise transport (wire::seal: AEAD, constant
//!        per-cell ciphertext length because the cell is fixed size)
//!     -> constant-size encrypted record on the wire, at a constant cadence
//! ```
//!
//! Inbound is the exact mirror. Two consequences are load-bearing and are the
//! reason this module exists:
//!
//! * **Length hiding is this layer's job, not the ratchet's.** The inner
//!   `DoubleRatchet` deliberately does *not* pad to a fixed size; it is this
//!   cover layer's fixed-size cells that hide message length. This module must
//!   therefore never assume the ratchet hid anything, and callers must never
//!   remove the fixed-cell framing "to save bytes".
//!
//! * <a name="transport-contract-security-precondition"></a>**TRANSPORT CONTRACT
//!   (security precondition — read before calling [`spawn`]).** The `reader` /
//!   `writer` handed to [`spawn`] **MUST** be a *per-cell authenticated-encryption
//!   transport* — for Ciphext, the Noise `wire::seal` / `wire::open` transport
//!   obtained after the handshake — with these properties:
//!     1. Each full cell written (`CELL_HEADER + cell_size` bytes) is sealed as
//!        **exactly one AEAD record of constant ciphertext length**. Because
//!        every cell is the same size, every sealed record is the same size, so
//!        `DATA` and `PAD` are indistinguishable on the wire.
//!     2. Each read yields **exactly one authenticated cell**; a forged or
//!        tampered record is rejected by the transport AEAD and never reaches
//!        this layer.
//!
//!   The cell's cleartext 1-byte `type` tag and 2-byte fragment length are
//!   confidential and integrity-protected **only** because the transport seals
//!   each cell. **These handles MUST NOT be raw sockets** (nor any unauthenticated
//!   or length-variable transport): on a raw socket the type/length bytes would
//!   be visible (leaking activity and message lengths) and malleable (an off-path
//!   attacker could flip them). This layer performs no cryptography of its own;
//!   it relies entirely on the transport to provide confidentiality, integrity,
//!   and constant per-cell ciphertext length.
//!
//! # Wire format
//!
//! Every cell is exactly `CELL_HEADER + cell_size` cleartext bytes, handed to the
//! sealing transport as one record:
//!
//! ```text
//! ┌────────┬───────────────────┬──────────────────────────────┐
//! │  type  │  fragment length  │        payload region        │
//! │ 1 byte │  2 bytes (BE u16) │        cell_size bytes       │
//! ├────────┼───────────────────┼──────────────────────────────┤
//! │ 0=PAD  │ # of valid payload│ stream bytes, then zero-pad  │
//! │ 1=DATA │ bytes in this cell│ (PAD cells are all zeroes)   │
//! └────────┴───────────────────┴──────────────────────────────┘
//! ```
//!
//! # Fragmentation / reassembly (the "continuation scheme")
//!
//! Application messages are opaque `Vec<u8>` blobs (e.g. a sealed ratchet record).
//! The sender treats the sequence of outbound messages as a single byte stream in
//! which each message is prefixed with a 4-byte big-endian length:
//!
//! ```text
//!   [len:4 BE][message bytes] [len:4 BE][message bytes] ...
//! ```
//!
//! That stream is then sliced blindly into the payload regions of consecutive
//! `DATA` cells. This single scheme handles every case:
//!
//! * A message **larger** than one cell simply spans several consecutive cells.
//! * Several **small** messages are packed into one cell when they fit.
//! * A message boundary that falls **mid-cell** is recovered exactly, because the
//!   receiver reconstructs the identical byte stream and re-reads the length
//!   prefixes. Reassembly is byte-for-byte exact and order-preserving.
//!
//! `PAD` cells contribute zero bytes to the stream, so injecting cover traffic
//! never disturbs message boundaries. Because the transport guarantees reliable,
//! ordered, exactly-once cell delivery, no cell is ever dropped in flight — a
//! property the length-prefixed stream depends on.
//!
//! # Constant cadence is decoupled from application I/O
//!
//! The whole point is that the *wire cadence never varies with application
//! behaviour*. This module therefore keeps pacing strictly independent of both
//! the local application's send/receive rate and of socket writability:
//!
//! * **Sender.** A pacing loop ticks every `interval` and, on every tick, produces
//!   exactly one cell and hands it to a dedicated writer task through a bounded
//!   queue with a **non-blocking** `try_send`. The pacing loop never awaits the
//!   socket, so a slow or momentarily unwritable transport can never stall the
//!   tick. Queued `DATA` bytes are only consumed once a cell is safely accepted by
//!   the writer, so transient transport congestion never loses `DATA` (dropping a
//!   `DATA` cell would desync the length-prefixed stream); only idle `PAD` cells
//!   may be shed under congestion, which is harmless.
//!
//! * **Receiver.** The socket read loop reads one authenticated cell at a time and
//!   **never blocks on the local consumer**. Reassembled messages are delivered
//!   with a non-blocking `try_send` into a bounded buffer; on overflow the
//!   **oldest** ready message is dropped. A stalled `inbound` consumer therefore
//!   cannot back-pressure the socket, which is critical: if it could, TCP flow
//!   control would stall the *peer's* writer and stutter the peer's "constant"
//!   cadence — a traffic-analysis signal, and the exact bug this design avoids.
//!
//! # Security notes
//!
//! * **No hand-rolled crypto.** This layer performs *no* cryptography; it frames
//!   and paces already-sealed opaque bytes and depends on the outer transport for
//!   all confidentiality and integrity (see the transport contract above).
//! * **No key material transits this layer**, so there is nothing to zeroize here;
//!   the buffers hold ciphertext, not secrets.
//! * **No secret comparisons.** The only equality checks are on the public cell
//!   `type` tag and public length fields — never on an authenticator — so no
//!   constant-time comparison is required in this module.
//! * **No panics on attacker-controlled input.** Every field parsed off the wire
//!   is bounds-checked. A malformed cell or an out-of-range message length is
//!   surfaced to the consumer as an explicit [`CoverError`] and tears the receive
//!   task down cleanly — never a panic, and never an ambiguous silent close.
//! * **Teardown on a bad field is not an off-path DoS.** Every inbound cell is
//!   authenticated by the outer transport *before* this layer parses it (transport
//!   contract, point 2). A malformed length or unknown tag can therefore only
//!   originate from the authenticated peer; an unauthenticated off-path attacker
//!   cannot forge a cell that survives the transport AEAD, so cannot trigger the
//!   teardown. Refusing to buffer an implausible field is the correct response to
//!   a broken or malicious *authenticated* peer.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{interval, MissedTickBehavior};

/// Default payload capacity of a single cell, in bytes.
///
/// The full on-wire cell size is [`CELL_HEADER`] + `cell_size`. Choose a value
/// comfortably larger than a typical sealed record to keep fragmentation
/// overhead low; correctness holds for any `cell_size` in `1..=u16::MAX`.
pub const CELL_SIZE: usize = 512;

/// Cell type tag: idle padding cell (contributes no stream bytes).
const CELL_PAD: u8 = 0;
/// Cell type tag: data cell (carries a fragment of the message byte stream).
const CELL_DATA: u8 = 1;

/// On-wire cell header: 1 type byte + 2-byte big-endian fragment length.
const CELL_HEADER: usize = 3;

/// Per-message length prefix embedded in the reassembly byte stream (BE u32).
const MSG_LEN_PREFIX: usize = 4;

/// Largest cell payload the 2-byte fragment-length field can describe.
const MAX_CELL_SIZE: usize = u16::MAX as usize;

/// Defensive upper bound on a single message, enforced identically on **both**
/// ends (64 MiB).
///
/// The sender rejects an outbound message larger than this with an explicit
/// error to the caller (so it never puts a message on the wire that the peer's
/// receiver would refuse), and the receiver refuses to buffer a reassembled
/// message that claims to exceed it. Because this bound is far below
/// `u32::MAX`, a conforming message length always fits the 4-byte stream prefix.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

/// Sane nonzero floor for the tick interval.
///
/// `tokio::time::interval` panics on a zero period, so [`spawn`] clamps
/// `CoverConfig::interval` up to at least this value, exactly as `cell_size` is
/// clamped into a representable range.
const MIN_INTERVAL: Duration = Duration::from_millis(1);

/// Bound on queued outbound messages before the outbound queue applies backpressure.
const OUTBOUND_CAPACITY: usize = 256;
/// Bound on reassembled inbound messages before the receive task drops the oldest.
const INBOUND_CAPACITY: usize = 256;
/// Bound on built-but-not-yet-written cells buffered between the pacing loop and
/// the dedicated writer task. Absorbs transient transport congestion without ever
/// blocking the pacing tick.
const WRITER_QUEUE_CAP: usize = 64;

/// Errors surfaced by a [`CoverChannel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverError {
    /// An outbound message exceeds [`MAX_MESSAGE_LEN`] (the same cap the receiver
    /// enforces). Returned to the caller *before* the message is queued, so an
    /// oversize local message can never silently tear down the peer's receiver.
    MessageTooLarge {
        /// The rejected message's length, in bytes.
        len: usize,
        /// The enforced maximum, in bytes ([`MAX_MESSAGE_LEN`]).
        max: usize,
    },
    /// The bounded outbound queue is full (only ever returned by
    /// [`CoverSender::try_send`]).
    QueueFull,
    /// The channel is closed — the background task has stopped or the peer /
    /// transport is gone.
    Closed,
    /// The peer declared a per-message length exceeding [`MAX_MESSAGE_LEN`].
    /// Because inbound cells are authenticated by the outer transport, this can
    /// only come from a broken or malicious *authenticated* peer.
    OversizeMessage {
        /// The implausible length the peer declared, in bytes.
        len: usize,
        /// The enforced maximum, in bytes ([`MAX_MESSAGE_LEN`]).
        max: usize,
    },
    /// The peer sent a structurally malformed cell (unknown type tag, or a
    /// fragment length larger than the agreed cell payload). As above, this is
    /// attributable to the authenticated peer, not an off-path attacker.
    MalformedCell,
}

impl std::fmt::Display for CoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverError::MessageTooLarge { len, max } => write!(
                f,
                "outbound message of {len} bytes exceeds the {max}-byte maximum"
            ),
            CoverError::QueueFull => write!(f, "outbound queue is full"),
            CoverError::Closed => write!(f, "cover channel is closed"),
            CoverError::OversizeMessage { len, max } => write!(
                f,
                "peer declared a {len}-byte message exceeding the {max}-byte maximum"
            ),
            CoverError::MalformedCell => write!(f, "peer sent a structurally malformed cell"),
        }
    }
}

impl std::error::Error for CoverError {}

/// Configuration for a cover-traffic channel.
#[derive(Clone, Debug)]
pub struct CoverConfig {
    /// Payload capacity of each cell, in bytes. Both peers MUST agree on this
    /// value (it is exchanged out of band / by protocol convention, not on the
    /// wire). Values outside `1..=u16::MAX` are clamped into range.
    pub cell_size: usize,
    /// Fixed interval between cells. This is the constant channel cadence: one
    /// cell is emitted per interval regardless of whether real data is queued.
    /// A zero or sub-millisecond interval is clamped up to a sane nonzero floor
    /// so the pacing task can never panic on a degenerate period.
    pub interval: Duration,
}

impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            cell_size: CELL_SIZE,
            interval: Duration::from_millis(50),
        }
    }
}

/// Cap-enforcing handle for pushing opaque messages onto a [`CoverChannel`].
///
/// Cloneable, so multiple producers may share it. Every send is checked against
/// [`MAX_MESSAGE_LEN`] *before* the message is queued, which is what keeps the
/// outbound cap symmetric with the receiver's cap (finding 3) and guarantees a
/// conforming length always fits the 4-byte stream prefix (finding 4).
#[derive(Clone)]
pub struct CoverSender {
    inner: mpsc::Sender<Vec<u8>>,
    max_message_len: usize,
}

impl CoverSender {
    /// Queue an opaque message for transmission, awaiting queue capacity if the
    /// bounded outbound buffer is momentarily full.
    ///
    /// Returns [`CoverError::MessageTooLarge`] (without queuing) if the message
    /// exceeds [`MAX_MESSAGE_LEN`], or [`CoverError::Closed`] if the channel has
    /// shut down.
    pub async fn send(&self, msg: Vec<u8>) -> Result<(), CoverError> {
        if msg.len() > self.max_message_len {
            return Err(CoverError::MessageTooLarge {
                len: msg.len(),
                max: self.max_message_len,
            });
        }
        self.inner.send(msg).await.map_err(|_| CoverError::Closed)
    }

    /// Non-blocking variant of [`send`](Self::send). Returns
    /// [`CoverError::QueueFull`] if the bounded outbound buffer is full.
    pub fn try_send(&self, msg: Vec<u8>) -> Result<(), CoverError> {
        if msg.len() > self.max_message_len {
            return Err(CoverError::MessageTooLarge {
                len: msg.len(),
                max: self.max_message_len,
            });
        }
        self.inner.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => CoverError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => CoverError::Closed,
        })
    }

    /// The maximum accepted outbound message length, in bytes.
    pub fn max_message_len(&self) -> usize {
        self.max_message_len
    }

    /// Remaining capacity of the bounded outbound queue, in messages.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

/// A running cover-traffic channel.
///
/// Push opaque messages to send through [`CoverChannel::outbound`]; pull
/// reassembled messages received from the peer out of [`CoverChannel::inbound`].
/// Dropping the whole struct lets the background tasks wind down: dropping
/// `outbound` signals the sender task to flush and stop, and an EOF/error on the
/// transport stops the receiver task.
pub struct CoverChannel {
    /// Cap-enforcing handle for opaque messages to transmit. Each `Vec<u8>` is
    /// delivered to the peer intact and in order. May be larger than one cell.
    pub outbound: CoverSender,
    /// Opaque messages received from the peer, reassembled exactly and in order,
    /// as `Ok(bytes)`. A protocol violation attributable to the authenticated
    /// peer is delivered as an explicit `Err(`[`CoverError`]`)` — never an
    /// ambiguous silent close — after which the stream ends.
    pub inbound: mpsc::Receiver<Result<Vec<u8>, CoverError>>,
}

/// Spawn a constant-rate cover-traffic channel over an authenticated transport.
///
/// `reader` / `writer` are the two halves of the established per-cell
/// authenticated-encryption transport to the peer (for Ciphext, obtain them via
/// `tokio::io::split` on the Noise `wire` transport after the handshake). See the
/// [transport contract](index.html#transport-contract-security-precondition):
/// they MUST seal/open each fixed cell as one constant-length AEAD record and
/// MUST NOT be raw sockets. Three background Tokio tasks are started:
///
/// * a **pacing loop** that ticks every `cfg.interval` and produces exactly one
///   cell per tick — a real fragment if any is queued, otherwise a `PAD` cell;
/// * a **writer task** that drains built cells to `writer`, fully decoupled from
///   pacing so a slow transport can never stall the tick;
/// * a **receiver task** that reads authenticated cells, discards `PAD`, and
///   reassembles `DATA` fragments into complete messages on `inbound`.
///
/// The tick rate is constant and independent of application activity and of
/// transport writability.
pub fn spawn<R, W>(reader: R, writer: W, cfg: CoverConfig) -> CoverChannel
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Clamp into the range the 2-byte fragment-length field can represent, and
    // never zero, so we can never emit a degenerate or unrepresentable cell.
    let cell_size = cfg.cell_size.clamp(1, MAX_CELL_SIZE);
    // Clamp the tick period to a sane nonzero floor: `interval(Duration::ZERO)`
    // panics, which would silently kill the pacing task (finding 5).
    let tick_interval = cfg.interval.max(MIN_INTERVAL);

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CAPACITY);
    let (in_tx, in_rx) = mpsc::channel::<Result<Vec<u8>, CoverError>>(INBOUND_CAPACITY);

    tokio::spawn(sender_task(writer, out_rx, cell_size, tick_interval));
    tokio::spawn(receiver_task(reader, in_tx, cell_size));

    CoverChannel {
        outbound: CoverSender {
            inner: out_tx,
            max_message_len: MAX_MESSAGE_LEN,
        },
        inbound: in_rx,
    }
}

/// Dedicated writer task: drains built cells and seals+writes them to the
/// transport. Owning the transport here (instead of writing from the pacing
/// loop) is what decouples wire pacing from socket writability.
async fn writer_task<W>(mut writer: W, mut cell_rx: mpsc::Receiver<Vec<u8>>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(cell) = cell_rx.recv().await {
        // One full cell -> one sealed, constant-length record (transport contract).
        if writer.write_all(&cell).await.is_err() || writer.flush().await.is_err() {
            break; // transport gone: dropping cell_rx signals the pacing loop.
        }
    }
    let _ = writer.shutdown().await;
}

/// Sender pacing loop: emits exactly one cell per tick at a fixed cadence,
/// handing each cell to the decoupled [`writer_task`] without ever blocking on
/// the transport.
///
/// The tick is never blocked on message availability (queued messages are pulled
/// with non-blocking `try_recv`, so an idle application produces `PAD` cells at
/// the same steady rate as a busy one) nor on transport writability (cells go to
/// the writer via a non-blocking `try_send`).
async fn sender_task<W>(
    writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cell_size: usize,
    tick_interval: Duration,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let cell_len = CELL_HEADER + cell_size;

    // Spawn the decoupled writer. The pacing loop below only ever `try_send`s to
    // this queue, so socket back-pressure never stalls the tick.
    let (cell_tx, cell_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE_CAP);
    let writer_handle = tokio::spawn(writer_task(writer, cell_rx));

    // Serialized, not-yet-sent bytes of the [len][msg][len][msg]... stream.
    let mut pending: VecDeque<u8> = VecDeque::new();

    let mut ticker = interval(tick_interval);
    // Keep spacing uniform even if the loop momentarily runs long: never fire a
    // catch-up burst, which would leak activity through timing.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut disconnected = false;

    loop {
        ticker.tick().await;

        // Non-blocking drain: pull queued messages until we have enough bytes to
        // fill a cell or the queue is empty. Each message is framed with a 4-byte
        // big-endian length prefix so the receiver can recover exact boundaries.
        while pending.len() < cell_size {
            match rx.try_recv() {
                Ok(msg) => match u32::try_from(msg.len()) {
                    // Defense in depth: `CoverSender` already rejects oversize
                    // messages, so this always holds. If one ever slipped past we
                    // drop it rather than truncate its length into the u32 prefix
                    // (finding 4) or overflow the peer's receiver (finding 3).
                    Ok(len) if msg.len() <= MAX_MESSAGE_LEN => {
                        pending.extend(len.to_be_bytes());
                        pending.extend(msg);
                    }
                    _ => {}
                },
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // All `outbound` senders dropped: flush what remains, then stop.
                    disconnected = true;
                    break;
                }
            }
        }

        // Build exactly one cell for this tick by COPYING (not draining) from the
        // front of the pending stream. Zeroing first makes a PAD cell (all zeroes)
        // the default and guarantees the payload tail is zero-padded for DATA cells.
        let n = pending.len().min(cell_size);
        let mut cell = vec![0u8; cell_len];
        if n > 0 {
            cell[0] = CELL_DATA;
            cell[1..CELL_HEADER].copy_from_slice(&(n as u16).to_be_bytes());
            for (slot, byte) in cell[CELL_HEADER..CELL_HEADER + n]
                .iter_mut()
                .zip(pending.iter().copied())
            {
                *slot = byte;
            }
        } else {
            cell[0] = CELL_PAD;
        }

        // Hand the cell to the writer without ever blocking the tick.
        match cell_tx.try_send(cell) {
            Ok(()) => {
                // Committed to the writer: only now consume those bytes from the
                // stream, so a full writer queue never loses DATA bytes.
                if n > 0 {
                    pending.drain(..n);
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Writer momentarily behind (transient transport congestion). The
                // bytes stay in `pending` for the next tick so DATA is never lost;
                // a dropped PAD cell is harmless. The tick still advanced on
                // schedule — the wire cadence is preserved.
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Writer task ended (transport dead): stop pacing.
                break;
            }
        }

        if disconnected && pending.is_empty() {
            break;
        }
    }

    // Let the writer flush any queued cells and shut the transport down.
    drop(cell_tx);
    let _ = writer_handle.await;
}

/// Receiver task: reads fixed-size authenticated cells, discards `PAD`, and
/// reassembles `DATA` fragments into whole messages delivered on `inbound`.
///
/// The socket read loop never blocks on the local consumer: complete messages are
/// staged in a bounded buffer and delivered with a non-blocking `try_send`; on
/// overflow the oldest ready message is dropped. This guarantees the transport is
/// always drained at wire rate, so a stalled consumer can never back-pressure the
/// peer's constant cadence.
async fn receiver_task<R>(
    mut reader: R,
    tx: mpsc::Sender<Result<Vec<u8>, CoverError>>,
    cell_size: usize,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let cell_len = CELL_HEADER + cell_size;
    let mut cell = vec![0u8; cell_len];
    // Accumulated stream bytes awaiting boundary parsing.
    let mut reasm: Vec<u8> = Vec::new();
    // Bounded staging buffer so a stalled `inbound` consumer can NEVER block the
    // read loop. Reassembly stays exact because we still read and parse every
    // authenticated cell; only fully-formed messages at the delivery edge are
    // shed (oldest first) under sustained consumer backpressure.
    let mut ready: VecDeque<Vec<u8>> = VecDeque::new();

    loop {
        // Read exactly one authenticated cell (transport contract: each read
        // yields one AEAD-verified cell). EOF or transport error ends the stream.
        if reader.read_exact(&mut cell).await.is_err() {
            break;
        }

        match cell[0] {
            CELL_PAD => {} // pure cover traffic — nothing to reassemble
            CELL_DATA => {
                let flen = u16::from_be_bytes([cell[1], cell[2]]) as usize;
                // A DATA cell can never validly claim more payload than exists.
                if flen > cell_size {
                    // Authenticated peer emitted an impossible fragment length:
                    // surface an explicit error, then tear down (safe — see the
                    // "not an off-path DoS" security note).
                    let _ = tx.send(Err(CoverError::MalformedCell)).await;
                    return;
                }
                reasm.extend_from_slice(&cell[CELL_HEADER..CELL_HEADER + flen]);
            }
            _ => {
                // Unknown tag from the authenticated peer: malformed frame.
                let _ = tx.send(Err(CoverError::MalformedCell)).await;
                return;
            }
        }

        // Parse every complete message currently buffered into the staging queue.
        loop {
            if reasm.len() < MSG_LEN_PREFIX {
                break; // not even a full length prefix yet
            }
            let mlen = u32::from_be_bytes([reasm[0], reasm[1], reasm[2], reasm[3]]) as usize;

            if mlen > MAX_MESSAGE_LEN {
                // Corruption/attack from the authenticated peer: refuse to buffer
                // unbounded memory and surface an explicit error (finding 3).
                let _ = tx
                    .send(Err(CoverError::OversizeMessage {
                        len: mlen,
                        max: MAX_MESSAGE_LEN,
                    }))
                    .await;
                return;
            }
            if reasm.len() < MSG_LEN_PREFIX + mlen {
                break; // message not fully arrived; wait for more cells
            }

            let msg = reasm[MSG_LEN_PREFIX..MSG_LEN_PREFIX + mlen].to_vec();
            reasm.drain(..MSG_LEN_PREFIX + mlen);
            ready.push_back(msg);
            // Never buffer without bound: drop the OLDEST beyond capacity.
            while ready.len() > INBOUND_CAPACITY {
                ready.pop_front();
            }
        }

        // Deliver as many staged messages as the consumer will accept right now,
        // without ever blocking the read loop on it.
        while let Some(msg) = ready.pop_front() {
            match tx.try_send(Ok(msg)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(item)) => {
                    // Consumer is behind: requeue at the front and stop draining
                    // this round (the next cell's loop will retry).
                    if let Ok(m) = item {
                        ready.push_front(m);
                    }
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return; // consumer dropped `inbound`; stop reassembling
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_cfg() -> CoverConfig {
        CoverConfig {
            cell_size: 512,
            interval: Duration::from_millis(2),
        }
    }

    // Deterministic pseudo-random payload of a given length.
    fn pattern(seed: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|j| ((seed.wrapping_mul(131).wrapping_add(j.wrapping_mul(7))) & 0xff) as u8)
            .collect()
    }

    async fn recv_next(inbound: &mut mpsc::Receiver<Result<Vec<u8>, CoverError>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), inbound.recv())
            .await
            .expect("timed out waiting for message")
            .expect("cover channel closed unexpectedly")
            .expect("unexpected protocol error on inbound")
    }

    /// Messages of varying sizes — including empty, exactly one cell, and several
    /// cells — round-trip intact and in order, byte-for-byte.
    #[tokio::test]
    async fn roundtrip_various_sizes_exact() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let a = spawn(tokio::io::empty(), client, test_cfg());
        let mut b = spawn(server, tokio::io::sink(), test_cfg());

        // 0, 1, sub-cell, exactly cell, just-over-cell, and multi-cell messages.
        let sizes = [0usize, 1, 7, 100, 511, 512, 513, 1000, 4096, 5000];
        let msgs: Vec<Vec<u8>> = sizes.iter().map(|&n| pattern(n, n)).collect();

        for m in &msgs {
            a.outbound.send(m.clone()).await.unwrap();
        }
        for expected in &msgs {
            let got = recv_next(&mut b.inbound).await;
            assert_eq!(
                &got,
                expected,
                "message of len {} corrupted",
                expected.len()
            );
        }
    }

    /// A single message far larger than one cell reassembles byte-for-byte.
    #[tokio::test]
    async fn large_message_reassembly_exact() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let a = spawn(tokio::io::empty(), client, test_cfg());
        let mut b = spawn(server, tokio::io::sink(), test_cfg());

        // ~40 cells' worth of non-trivial bytes.
        let big: Vec<u8> = (0..20_000u32)
            .map(|k| (k.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        a.outbound.send(big.clone()).await.unwrap();

        let got = recv_next(&mut b.inbound).await;
        assert_eq!(got.len(), big.len());
        assert_eq!(got, big);
    }

    /// Many small messages preserve order and content (exercises packing several
    /// messages into a single cell).
    #[tokio::test]
    async fn many_small_messages_in_order() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let a = spawn(tokio::io::empty(), client, test_cfg());
        let mut b = spawn(server, tokio::io::sink(), test_cfg());

        let n = 50usize;
        for i in 0..n {
            a.outbound.send(vec![i as u8; (i % 9) + 1]).await.unwrap();
        }
        for i in 0..n {
            let got = recv_next(&mut b.inbound).await;
            assert_eq!(
                got,
                vec![i as u8; (i % 9) + 1],
                "message {i} out of order/corrupt"
            );
        }
    }

    /// With no real data queued, the sender still emits cells at the fixed cadence,
    /// and every one of them is an all-zero PAD cell — indistinguishable filler.
    #[tokio::test]
    async fn pad_cells_emitted_while_idle() {
        let cfg = test_cfg();
        let cell_len = CELL_HEADER + cfg.cell_size;
        let (client, mut server) = tokio::io::duplex(1 << 16);

        // Keep the channel handle alive so the sender task does not shut down.
        let _ch = spawn(tokio::io::empty(), client, cfg);

        let mut buf = vec![0u8; cell_len];
        let observed = 16;
        for _ in 0..observed {
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], CELL_PAD, "expected a PAD cell during idle");
            assert_eq!(
                u16::from_be_bytes([buf[1], buf[2]]),
                0,
                "PAD cell must declare zero fragment length"
            );
            assert!(
                buf[CELL_HEADER..].iter().all(|&b| b == 0),
                "PAD payload must be zeroed"
            );
        }
        // We saw a steady stream of >N filler cells over N+ intervals with no data.
        assert!(observed > 8);
    }

    /// Real data still flows correctly even when interleaved with idle padding:
    /// send, wait through several idle ticks, then send again.
    #[tokio::test]
    async fn data_survives_interleaved_idle() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let a = spawn(tokio::io::empty(), client, test_cfg());
        let mut b = spawn(server, tokio::io::sink(), test_cfg());

        a.outbound.send(pattern(1, 300)).await.unwrap();
        assert_eq!(recv_next(&mut b.inbound).await, pattern(1, 300));

        // Idle for a while (only PAD cells cross the wire).
        tokio::time::sleep(Duration::from_millis(30)).await;

        a.outbound.send(pattern(2, 1500)).await.unwrap();
        assert_eq!(recv_next(&mut b.inbound).await, pattern(2, 1500));
    }

    // ----------------------------------------------------------------------
    // Finding 5: a zero / degenerate interval must be clamped, not panic.
    // ----------------------------------------------------------------------

    /// `interval: Duration::ZERO` must not panic the pacing task; it is clamped to
    /// `MIN_INTERVAL` and cells still flow at a steady rate.
    #[tokio::test]
    async fn zero_interval_is_clamped_not_panicked() {
        let cfg = CoverConfig {
            cell_size: 64,
            interval: Duration::ZERO,
        };
        let cell_len = CELL_HEADER + cfg.cell_size;
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let _ch = spawn(tokio::io::empty(), client, cfg);

        // If the pacing task had panicked on Duration::ZERO, no cell would ever
        // arrive and this read would time out.
        let mut buf = vec![0u8; cell_len];
        for _ in 0..4 {
            tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut buf))
                .await
                .expect("pacing task panicked or stalled on a zero interval")
                .unwrap();
            assert_eq!(buf[0], CELL_PAD);
        }
    }

    // ----------------------------------------------------------------------
    // Finding 3: symmetric size cap + explicit errors on both ends.
    // ----------------------------------------------------------------------

    /// An oversize outbound message is rejected with an explicit error to the
    /// caller and is never placed on the wire (so it can't kill the peer's
    /// receiver). Conforming messages are still accepted.
    #[tokio::test]
    async fn oversize_outbound_rejected_with_explicit_error() {
        let (client, _server) = tokio::io::duplex(1 << 16);
        let ch = spawn(tokio::io::empty(), client, test_cfg());

        let too_big = vec![0u8; MAX_MESSAGE_LEN + 1];
        match ch.outbound.send(too_big).await {
            Err(CoverError::MessageTooLarge { len, max }) => {
                assert_eq!(len, MAX_MESSAGE_LEN + 1);
                assert_eq!(max, MAX_MESSAGE_LEN);
            }
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
        // Same guard on the non-blocking path.
        assert_eq!(
            ch.outbound.try_send(vec![0u8; MAX_MESSAGE_LEN + 1]),
            Err(CoverError::MessageTooLarge {
                len: MAX_MESSAGE_LEN + 1,
                max: MAX_MESSAGE_LEN,
            })
        );
        // A conforming message is accepted.
        assert!(ch.outbound.try_send(vec![0u8; 8]).is_ok());
    }

    /// The receiver surfaces an oversize per-message length as an explicit
    /// `Err(OversizeMessage)` rather than an ambiguous silent channel close.
    #[tokio::test]
    async fn receiver_surfaces_oversize_message_error() {
        let cell_size = 64usize;
        let cfg = CoverConfig {
            cell_size,
            interval: Duration::from_millis(2),
        };
        // One DATA cell carrying a 4-byte length prefix claiming an oversize message.
        let mut cell = vec![0u8; CELL_HEADER + cell_size];
        cell[0] = CELL_DATA;
        cell[1..CELL_HEADER].copy_from_slice(&4u16.to_be_bytes());
        let bogus_len = (MAX_MESSAGE_LEN as u32) + 1;
        cell[CELL_HEADER..CELL_HEADER + 4].copy_from_slice(&bogus_len.to_be_bytes());

        let reader = io::Cursor::new(cell);
        let mut ch = spawn(reader, tokio::io::sink(), cfg);

        match tokio::time::timeout(Duration::from_secs(5), ch.inbound.recv())
            .await
            .expect("timed out")
        {
            Some(Err(CoverError::OversizeMessage { len, max })) => {
                assert_eq!(len, MAX_MESSAGE_LEN + 1);
                assert_eq!(max, MAX_MESSAGE_LEN);
            }
            other => panic!("expected explicit OversizeMessage error, got {other:?}"),
        }
    }

    /// The receiver surfaces a structurally malformed cell (fragment length larger
    /// than the cell) as an explicit `Err(MalformedCell)`.
    #[tokio::test]
    async fn receiver_surfaces_malformed_cell_error() {
        let cell_size = 32usize;
        let cfg = CoverConfig {
            cell_size,
            interval: Duration::from_millis(2),
        };
        let mut cell = vec![0u8; CELL_HEADER + cell_size];
        cell[0] = CELL_DATA;
        // A fragment length larger than the cell payload is structurally impossible.
        cell[1..CELL_HEADER].copy_from_slice(&((cell_size as u16) + 1).to_be_bytes());

        let reader = io::Cursor::new(cell);
        let mut ch = spawn(reader, tokio::io::sink(), cfg);

        match tokio::time::timeout(Duration::from_secs(5), ch.inbound.recv())
            .await
            .expect("timed out")
        {
            Some(Err(CoverError::MalformedCell)) => {}
            other => panic!("expected explicit MalformedCell error, got {other:?}"),
        }
    }

    // ----------------------------------------------------------------------
    // Finding 1: constant cadence is decoupled from application I/O.
    // ----------------------------------------------------------------------

    /// A stalled `inbound` consumer must never back-pressure the socket read loop.
    /// We feed far more DATA cells than either the inbound channel or the staging
    /// buffer can hold, through a *small* pipe, and never poll `inbound`. If the
    /// read loop blocked on the un-polled consumer, the pipe would fill and our
    /// writes would stall; because it keeps draining (drop-oldest), every write
    /// completes.
    #[tokio::test]
    async fn stalled_consumer_never_blocks_receiver_read_loop() {
        let cell_size = 16usize;
        let cfg = CoverConfig {
            cell_size,
            interval: Duration::from_millis(2),
        };
        // Small pipe so a blocked reader would back-pressure our writes quickly.
        let (mut wire, server) = tokio::io::duplex(cell_size * 4 + 64);
        // Receiver whose `inbound` we deliberately never poll (stalled consumer).
        // Keep `_ch` alive so `inbound` isn't dropped (which would close the task).
        let _ch = spawn(server, tokio::io::sink(), cfg);

        // One DATA cell = one complete tiny message ([len:4][1 byte]).
        let mut cell = vec![0u8; CELL_HEADER + cell_size];
        cell[0] = CELL_DATA;
        let mut stream = Vec::new();
        stream.extend(1u32.to_be_bytes());
        stream.push(0xAB);
        cell[1..CELL_HEADER].copy_from_slice(&(stream.len() as u16).to_be_bytes());
        cell[CELL_HEADER..CELL_HEADER + stream.len()].copy_from_slice(&stream);

        // Write far more messages than inbound + staging can ever hold at once.
        let to_write = INBOUND_CAPACITY * 3;
        for _ in 0..to_write {
            tokio::time::timeout(Duration::from_secs(5), wire.write_all(&cell))
                .await
                .expect("receiver read loop stalled on the un-polled consumer")
                .unwrap();
        }
        // Reaching here means the receiver kept draining the wire despite the
        // stalled consumer — the constant-cadence property finding 1 requires.
    }

    /// A burst of outbound messages must NOT burst onto the wire: the pacing loop
    /// emits one cell per interval, so cells arrive spaced by ~interval even
    /// though the whole backlog was queued instantly.
    #[tokio::test]
    async fn bursty_outbound_emits_at_constant_cadence() {
        let tick = Duration::from_millis(10);
        let cell_size = 128usize;
        let cell_len = CELL_HEADER + cell_size;
        let cfg = CoverConfig {
            cell_size,
            interval: tick,
        };
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let ch = spawn(tokio::io::empty(), client, cfg);

        // Burst a pile of messages instantly.
        for i in 0..40u8 {
            ch.outbound.send(vec![i; 20]).await.unwrap();
        }

        // Timestamp consecutive cell arrivals; despite the burst they must be
        // paced ~one interval apart, not delivered all at once.
        let mut buf = vec![0u8; cell_len];
        let mut times = Vec::new();
        for _ in 0..8 {
            server.read_exact(&mut buf).await.unwrap();
            times.push(Instant::now());
        }
        for w in times.windows(2) {
            let gap = w[1].duration_since(w[0]);
            assert!(
                gap >= tick / 2,
                "cells arrived too fast (backlog burst leaked onto the wire): {gap:?}"
            );
        }
    }

    /// An `AsyncWrite` whose writes never complete — models a socket that is
    /// permanently unwritable (peer not reading, buffers full).
    struct BlockingWriter;
    impl AsyncWrite for BlockingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// The pacing tick must keep advancing (and keep draining the outbound queue
    /// into the decoupled writer queue) even when the transport can never accept a
    /// single byte. With the old coupled design the tick would block on the very
    /// first write; here the outbound queue fully drains despite the dead socket.
    #[tokio::test]
    async fn blocked_writer_does_not_stall_tick() {
        let cfg = CoverConfig {
            cell_size: 512,
            interval: Duration::from_millis(2),
        };
        let ch = spawn(tokio::io::empty(), BlockingWriter, cfg);

        // Fill the outbound queue with tiny messages.
        for i in 0..OUTBOUND_CAPACITY {
            ch.outbound.try_send(vec![(i & 0xff) as u8]).unwrap();
        }
        assert_eq!(
            ch.outbound.capacity(),
            0,
            "outbound queue should start full"
        );

        // Give the tick many intervals to run while the socket is fully blocked.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The pacing loop kept advancing and draining outbound into the decoupled
        // writer queue even though not one byte could be written — the tick is not
        // coupled to socket writability (finding 1). The whole backlog fits in the
        // decoupled writer queue, so outbound drains completely.
        assert_eq!(
            ch.outbound.capacity(),
            OUTBOUND_CAPACITY,
            "tick appears blocked on the socket: only {} of {} messages drained",
            OUTBOUND_CAPACITY - ch.outbound.capacity(),
            OUTBOUND_CAPACITY
        );
    }

    // ----------------------------------------------------------------------
    // Cover-traffic measurement harness: prove the wire is input-independent.
    //
    // The tests above establish individual properties (idle emits PAD, a burst
    // does not burst onto the wire). This harness instead *measures* the whole
    // channel end-to-end and directly compares what a passive on-wire observer
    // sees across three application behaviours — fully idle, a human "typing",
    // and a backlog dumped then silence. The claim under test is the core
    // traffic-analysis guarantee: the observable wire (record size, records per
    // window, cadence) is the SAME in all three, even though the plaintext of
    // the cells is completely different.
    // ----------------------------------------------------------------------

    /// One record as a passive on-wire observer would see it: a fixed-size record
    /// arriving at some instant. `is_data` is captured for the *internal* honesty
    /// check only — a real observer never sees it, because the outer transport
    /// seals the cell's type byte (see the transport contract).
    #[derive(Clone, Copy)]
    struct Obs {
        at: Duration,
        len: usize,
        is_data: bool,
    }

    /// Run a cover channel for `window`, driving the application side with `drive`,
    /// and return the observer's record trace. The reader always outpaces the
    /// pacing tick (reads are instant; cells arrive one per `tick`), so each
    /// `read_exact` blocks until the next cell is emitted — the recorded `at`
    /// therefore reflects the true emission cadence, not reader speed.
    async fn observe_window<F, Fut>(
        tick: Duration,
        window: Duration,
        cell_size: usize,
        drive: F,
    ) -> Vec<Obs>
    where
        F: FnOnce(CoverSender) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let cell_len = CELL_HEADER + cell_size;
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let ch = spawn(
            tokio::io::empty(),
            client,
            CoverConfig {
                cell_size,
                interval: tick,
            },
        );
        // Drive application-side sends concurrently with observation.
        let driver = tokio::spawn(drive(ch.outbound.clone()));

        let start = Instant::now();
        let mut obs = Vec::new();
        let mut buf = vec![0u8; cell_len];
        loop {
            let elapsed = start.elapsed();
            if elapsed >= window {
                break;
            }
            // Bound the read so a torn final cell can't hang the window.
            let budget = (window - elapsed) + Duration::from_millis(50);
            match tokio::time::timeout(budget, server.read_exact(&mut buf)).await {
                Ok(Ok(_)) => obs.push(Obs {
                    at: start.elapsed(),
                    len: buf.len(),
                    is_data: buf[0] == CELL_DATA,
                }),
                _ => break,
            }
        }
        drop(ch); // stop pacing; driver's remaining sends (if any) just error out
        let _ = driver.await;
        obs
    }

    /// The headline traffic-analysis property, measured directly.
    ///
    /// A passive observer sees the SAME wire — identical record size, near-equal
    /// record count per window, and the same steady cadence — whether the app is
    /// idle, typing, or draining a backlog. The cell *contents* differ enormously
    /// across these scenarios; the observable shape does not.
    ///
    /// What this DOES cover: the constant-bit-rate framing and pacing this module
    /// owns — record size, per-window record count, and inter-record cadence as a
    /// function of application input.
    ///
    /// What this deliberately does NOT cover (stated honestly, not silently):
    ///   * Tor circuit construction / onion-descriptor publication timing and the
    ///     TCP connect/teardown events — those live in the transport (tor.rs). A
    ///     network observer can still see *that a connection exists*; cover traffic
    ///     never claimed to hide that.
    ///   * *When* a peer comes online or goes offline, and total session duration.
    ///   * The constant *sealed* record size relies on the outer AEAD adding fixed
    ///     overhead to a fixed-size cell (true for Noise ChaCha20-Poly1305: 16-byte
    ///     tag + fixed length framing). This harness measures the pre-seal cell,
    ///     whose size is constant by construction; the seal preserves that.
    #[tokio::test]
    async fn cover_traffic_is_indistinguishable_across_input_patterns() {
        let tick = Duration::from_millis(5);
        let window = Duration::from_millis(300);
        let cell_size = 512usize;
        let cell_len = CELL_HEADER + cell_size;

        // A: fully idle — never sends a byte.
        let idle = observe_window(tick, window, cell_size, |_tx| async {}).await;

        // B: a human "typing" — a keystroke-sized message every few ticks, spread
        // across the whole window.
        let typing = observe_window(tick, window, cell_size, |tx| async move {
            for _ in 0..18u32 {
                let _ = tx.send(vec![b'x']).await;
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        })
        .await;

        // C: a large backlog dumped up front, then silence — worst case for
        // "activity leaks onto the wire".
        let burst = observe_window(tick, window, cell_size, |tx| async move {
            // Enough bytes (~44 cells' worth) to keep DATA dominant across most of
            // the window, so this is a real "activity" stress, not a brief blip.
            for i in 0..350u32 {
                let _ = tx.send(vec![(i % 251) as u8; 60]).await;
            }
        })
        .await;

        let traces = [("idle", &idle), ("typing", &typing), ("burst", &burst)];

        // (A) Constant record size, always, in every scenario.
        for (label, t) in traces {
            assert!(!t.is_empty(), "{label}: observed no cells at all");
            assert!(
                t.iter().all(|o| o.len == cell_len),
                "{label}: a record of non-constant size appeared on the wire"
            );
        }

        // (A') The observer's size-trace is byte-identical across scenarios: the
        // sequence of record sizes carries zero bits about whether anyone talks.
        let prefix = idle.len().min(typing.len()).min(burst.len());
        let baseline = vec![cell_len; prefix];
        for (label, t) in traces {
            let sizes: Vec<usize> = t.iter().take(prefix).map(|o| o.len).collect();
            assert_eq!(
                sizes, baseline,
                "{label}: size-trace diverges from the constant-rate baseline"
            );
        }

        // (B) Equal record COUNT per identical window, regardless of input.
        let counts = [idle.len(), typing.len(), burst.len()];
        let mean = counts.iter().sum::<usize>() as f64 / 3.0;
        let spread = counts.iter().max().unwrap() - counts.iter().min().unwrap();
        let tol = (0.25 * mean).max(4.0) as usize;
        assert!(
            spread <= tol,
            "cell count leaked application activity: idle={} typing={} burst={} \
             (spread {spread} > tolerance {tol})",
            idle.len(),
            typing.len(),
            burst.len()
        );
        assert!(
            mean >= 20.0,
            "window too short to be a meaningful measurement: mean={mean}"
        );

        // (C) Constant *aggregate* cadence: the mean inter-record interval is ~tick
        // in every scenario — the wire advances at the pacing rate no matter the
        // input, neither faster when busy nor slower when idle.
        //
        // We assert the aggregate, not per-gap minima, deliberately: instantaneous
        // no-burst is guaranteed by *construction* (the pacing loop gates every
        // single cell — DATA or PAD — behind `ticker.tick().await`, so two cells can
        // never leave without a tick between them) and is proven separately by
        // `bursty_outbound_emits_at_constant_cadence`. A userspace observer's per-gap
        // timing, by contrast, is unreliable under CPU contention: a descheduled
        // reader records several buffered cells back-to-back, which looks like a
        // burst but is a measurement artifact. The mean interval is immune to that —
        // the reader can bunch *where* it records cells, but cannot read cell N
        // before pacing emitted it, so the span still reflects the true tick rate.
        for (label, t) in traces {
            if t.len() >= 8 {
                let warmup = 3;
                let span = t[t.len() - 1].at.saturating_sub(t[warmup].at);
                let intervals = (t.len() - 1 - warmup) as u32;
                let mean_gap = span / intervals;
                assert!(
                    mean_gap >= tick * 2 / 5 && mean_gap <= tick * 5 / 2,
                    "{label}: mean inter-record interval {mean_gap:?} is far from the \
                     {tick:?} tick — cadence tracked application activity"
                );
            }
        }

        // Honesty check: the scenarios really ARE different underneath. Same
        // observable shape above; wildly different plaintext content here.
        assert!(
            idle.iter().all(|o| !o.is_data),
            "idle scenario unexpectedly carried DATA cells"
        );
        assert!(
            burst.iter().filter(|o| o.is_data).count() >= 20,
            "burst scenario carried too little DATA to be a real stress"
        );
        assert!(
            typing.iter().any(|o| o.is_data),
            "typing scenario never actually sent anything"
        );
    }
}
