//! Typed application messages carried inside the encrypted channel.
//!
//! The Noise transport gives us a reliable, ordered, encrypted stream of
//! records. On top of that we send *typed* frames so the same channel can carry
//! chat text and file transfers without ambiguity. Each frame is encoded to
//! bytes, sealed as one Noise record, and decoded on the far side.

use anyhow::{anyhow, bail, Result};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default cap on inbound file transfers in flight at once, so a peer can't open an
/// unbounded number of offers (each an open file handle + a partial file).
pub const MAX_CONCURRENT_FILES: usize = 16;

/// Consent gate for INBOUND files — the "nothing hits disk without consent"
/// security property, factored out of the app so it is testable without a
/// filesystem or a UI.
///
/// An offer is only *pending* until the user accepts it; a chunk is written to
/// disk only for an *accepted* transfer. This type decides **whether** bytes are
/// allowed; the actual disk sink is [`Incoming`]. The two together guarantee that
/// no byte of an unaccepted (or rejected, or unknown) transfer ever reaches disk.
#[derive(Default)]
pub struct FileGate {
    /// Offered but not yet consented to — name + size only; NO file is opened.
    pending: HashMap<[u8; 16], (String, u64)>,
    /// Consented transfers whose chunks may be written.
    accepted: HashSet<[u8; 16]>,
}

impl FileGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Transfers currently in flight (pending + accepted).
    pub fn in_flight(&self) -> usize {
        self.pending.len() + self.accepted.len()
    }

    /// Record an incoming offer as pending. Returns `false` (refused) if
    /// `max_concurrent` transfers are already in flight — no offer is stored, so a
    /// peer cannot open unbounded offers. A refused/accepted offer opens no file.
    pub fn offer(&mut self, id: [u8; 16], name: String, size: u64, max_concurrent: usize) -> bool {
        if self.in_flight() >= max_concurrent {
            return false;
        }
        self.pending.insert(id, (name, size));
        true
    }

    /// The user accepted: move the offer from pending to accepted and return its
    /// `(name, size)` so the caller can now open the disk sink. `None` if the id is
    /// unknown or was already rejected — so you can never open a sink without a
    /// prior pending offer.
    pub fn accept(&mut self, id: &[u8; 16]) -> Option<(String, u64)> {
        let v = self.pending.remove(id)?;
        self.accepted.insert(*id);
        Some(v)
    }

    /// The user declined: forget the pending offer. No file was ever opened, and
    /// the id can no longer be accepted.
    pub fn reject(&mut self, id: &[u8; 16]) {
        self.pending.remove(id);
    }

    /// May a chunk for this transfer be written to disk? True **only** after the
    /// user has accepted it — a pending, rejected, or unknown id returns `false`.
    pub fn accepts_chunk(&self, id: &[u8; 16]) -> bool {
        self.accepted.contains(id)
    }

    /// Forget a finished or failed transfer.
    pub fn finish(&mut self, id: &[u8; 16]) {
        self.pending.remove(id);
        self.accepted.remove(id);
    }
}

/// File payload per record. Kept comfortably under the Noise 65535-byte record
/// cap (minus framing and the AEAD tag).
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Hard ceiling on a single accepted incoming file (8 GiB). A peer offering more
/// than this is refused at [`Incoming::start`], and — regardless of the offer —
/// [`Incoming::write_chunk`] never writes past the offered size, so a malicious
/// or broken peer cannot stream unbounded chunks to fill the recipient's disk.
pub const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// A single application-level message.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// A chat line.
    Text(String),
    /// Announces an incoming file: a transfer id, its name, and total size.
    FileOffer {
        id: [u8; 16],
        name: String,
        size: u64,
    },
    /// One ordered slice of a file's bytes.
    FileChunk { id: [u8; 16], data: Vec<u8> },
    /// Marks a file transfer complete.
    FileEnd { id: [u8; 16] },
    /// The recipient consents to a [`Frame::FileOffer`]: only now may the sender
    /// stream chunks. This is what keeps a peer from writing to your disk
    /// unprompted — no byte is accepted until you accept the offer.
    FileAccept { id: [u8; 16] },
    /// The recipient declines a [`Frame::FileOffer`]; the sender must not stream.
    FileReject { id: [u8; 16] },
    /// An opaque group-protocol message carried over the pairwise sealed channel
    /// to/from the host relay. The bytes are the group layer's own framing
    /// (sender-key distributions are end-to-end encrypted to each recipient;
    /// group text is Sender-Key ciphertext) — the relay never reads inside them.
    Group(Vec<u8>),
}

const T_TEXT: u8 = 0x01;
const T_OFFER: u8 = 0x02;
const T_CHUNK: u8 = 0x03;
const T_END: u8 = 0x04;
const T_GROUP: u8 = 0x05;
const T_ACCEPT: u8 = 0x06;
const T_REJECT: u8 = 0x07;

impl Frame {
    /// Serialize to bytes: a 1-byte type tag followed by type-specific fields.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Text(s) => {
                let mut v = Vec::with_capacity(1 + s.len());
                v.push(T_TEXT);
                v.extend_from_slice(s.as_bytes());
                v
            }
            Frame::FileOffer { id, name, size } => {
                let nb = name.as_bytes();
                let mut v = Vec::with_capacity(1 + 16 + 8 + nb.len());
                v.push(T_OFFER);
                v.extend_from_slice(id);
                v.extend_from_slice(&size.to_be_bytes());
                v.extend_from_slice(nb);
                v
            }
            Frame::FileChunk { id, data } => {
                let mut v = Vec::with_capacity(1 + 16 + data.len());
                v.push(T_CHUNK);
                v.extend_from_slice(id);
                v.extend_from_slice(data);
                v
            }
            Frame::FileEnd { id } => {
                let mut v = Vec::with_capacity(1 + 16);
                v.push(T_END);
                v.extend_from_slice(id);
                v
            }
            Frame::FileAccept { id } => {
                let mut v = Vec::with_capacity(1 + 16);
                v.push(T_ACCEPT);
                v.extend_from_slice(id);
                v
            }
            Frame::FileReject { id } => {
                let mut v = Vec::with_capacity(1 + 16);
                v.push(T_REJECT);
                v.extend_from_slice(id);
                v
            }
            Frame::Group(data) => {
                let mut v = Vec::with_capacity(1 + data.len());
                v.push(T_GROUP);
                v.extend_from_slice(data);
                v
            }
        }
    }

    /// Parse bytes produced by [`Frame::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Frame> {
        let (&tag, rest) = bytes.split_first().ok_or_else(|| anyhow!("empty frame"))?;
        match tag {
            T_TEXT => Ok(Frame::Text(String::from_utf8_lossy(rest).into_owned())),
            T_OFFER => {
                if rest.len() < 24 {
                    bail!("short file offer");
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&rest[..16]);
                let mut sb = [0u8; 8];
                sb.copy_from_slice(&rest[16..24]);
                Ok(Frame::FileOffer {
                    id,
                    size: u64::from_be_bytes(sb),
                    name: String::from_utf8_lossy(&rest[24..]).into_owned(),
                })
            }
            T_CHUNK => {
                if rest.len() < 16 {
                    bail!("short file chunk");
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&rest[..16]);
                Ok(Frame::FileChunk {
                    id,
                    data: rest[16..].to_vec(),
                })
            }
            T_END => {
                if rest.len() < 16 {
                    bail!("short file end");
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&rest[..16]);
                Ok(Frame::FileEnd { id })
            }
            T_ACCEPT | T_REJECT => {
                if rest.len() < 16 {
                    bail!("short file accept/reject");
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&rest[..16]);
                Ok(if tag == T_ACCEPT {
                    Frame::FileAccept { id }
                } else {
                    Frame::FileReject { id }
                })
            }
            T_GROUP => Ok(Frame::Group(rest.to_vec())),
            other => bail!("unknown frame type {other:#04x}"),
        }
    }
}

/// A file transfer being received: bytes are streamed straight to disk so we
/// never hold a whole file in memory.
pub struct Incoming {
    pub name: String,
    pub size: u64,
    pub received: u64,
    pub path: PathBuf,
    file: std::fs::File,
}

impl Incoming {
    /// Begin receiving `name` of `size` bytes: pick a safe destination under the
    /// user's Downloads directory and open it for writing.
    ///
    /// Refuses an offer larger than [`MAX_FILE_SIZE`] before creating any file, so
    /// an implausible offer never even opens a handle.
    pub fn start(name: &str, size: u64) -> Result<Incoming> {
        if size > MAX_FILE_SIZE {
            bail!("offered file of {size} bytes exceeds the {MAX_FILE_SIZE}-byte limit");
        }
        let path = download_path(name)?;
        let file = std::fs::File::create(&path)
            .map_err(|e| anyhow!("cannot create {}: {e}", path.display()))?;
        Ok(Incoming {
            name: sanitize(name),
            size,
            received: 0,
            path,
            file,
        })
    }

    /// Append a received chunk to disk.
    ///
    /// Fails closed if the chunk would push the running total past the size the
    /// sender offered: the offered size is itself capped at [`start`](Self::start),
    /// so this bounds a transfer's on-disk footprint to `min(offer, MAX_FILE_SIZE)`
    /// and stops a peer from streaming unbounded chunks to fill the disk.
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        let new_total = accept_total(self.received, data.len(), self.size)?;
        self.file.write_all(data)?;
        self.received = new_total;
        Ok(())
    }

    /// Flush and finish.
    pub fn finish(mut self) -> Result<PathBuf> {
        self.file.flush()?;
        Ok(self.path)
    }
}

/// The running total after accepting `len` more bytes, or an error if that would
/// exceed the offered `size` (or overflow `u64`). The disk-fill guard lives here,
/// pure, so it can be tested without touching the filesystem.
fn accept_total(received: u64, len: usize, size: u64) -> Result<u64> {
    let new_total = received
        .checked_add(len as u64)
        .ok_or_else(|| anyhow!("file size counter overflow"))?;
    if new_total > size {
        bail!("peer sent more than the offered {size} bytes (would reach {new_total})");
    }
    Ok(new_total)
}

/// Strip any directory components and control characters from an offered name so
/// a peer can't write outside the download directory (path traversal).
fn sanitize(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("received-file");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    if cleaned.is_empty() {
        "received-file".to_string()
    } else {
        cleaned
    }
}

/// Choose a non-colliding path in the Downloads directory for an incoming file.
fn download_path(name: &str) -> Result<PathBuf> {
    let base = directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Downloads")))
        .ok_or_else(|| anyhow!("could not locate a Downloads directory"))?;
    std::fs::create_dir_all(&base)?;

    let safe = sanitize(name);
    let first = base.join(&safe);
    if !first.exists() {
        return Ok(first);
    }
    // Insert a counter before the extension: name-1.ext, name-2.ext, ...
    let path = Path::new(&safe);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path.extension().and_then(|s| s.to_str());
    for n in 1..10_000 {
        let candidate = match ext {
            Some(e) => base.join(format!("{stem}-{n}.{e}")),
            None => base.join(format!("{stem}-{n}")),
        };
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("too many files named like {safe}")
}

/// Human-readable byte size, e.g. "2.1 MB".
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip() {
        let f = Frame::Text("hello, world 🌍".into());
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn group_roundtrip() {
        let f = Frame::Group(vec![9, 8, 7, 0, 255, 42]);
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn file_frames_roundtrip() {
        let id = [7u8; 16];
        let offer = Frame::FileOffer {
            id,
            name: "plan.pdf".into(),
            size: 123456,
        };
        assert_eq!(Frame::decode(&offer.encode()).unwrap(), offer);

        let chunk = Frame::FileChunk {
            id,
            data: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(Frame::decode(&chunk.encode()).unwrap(), chunk);

        let end = Frame::FileEnd { id };
        assert_eq!(Frame::decode(&end.encode()).unwrap(), end);

        let accept = Frame::FileAccept { id };
        assert_eq!(Frame::decode(&accept.encode()).unwrap(), accept);
        let reject = Frame::FileReject { id };
        assert_eq!(Frame::decode(&reject.encode()).unwrap(), reject);
        // accept and reject must not decode to the same frame.
        assert_ne!(accept, reject);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[0xFF, 1, 2]).is_err());
        assert!(Frame::decode(&[T_OFFER, 0, 0]).is_err()); // too short
    }

    #[test]
    fn sanitize_blocks_traversal() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize("/abs/path/file.txt"), "file.txt");
        assert_eq!(sanitize("plain.txt"), "plain.txt");
    }

    #[test]
    fn human_size_reads_well() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2 * 1024 * 1024), "2.0 MB");
    }

    /// An offer larger than the hard cap is refused before any file is opened.
    #[test]
    fn start_rejects_oversize_offer() {
        match Incoming::start("huge.bin", MAX_FILE_SIZE + 1) {
            Err(e) => assert!(e.to_string().contains("exceeds"), "got: {e}"),
            Ok(_) => panic!("an over-cap offer must be refused (and must not open a file)"),
        }
    }

    // ---- File-consent gate (the "nothing to disk without consent" property) ----

    /// A pending offer is NOT writable; only accepting it opens the gate. This is
    /// the core consent guarantee: no chunk is accepted before the user says yes.
    #[test]
    fn file_gate_writes_only_after_consent() {
        let mut g = FileGate::new();
        let id = [1u8; 16];
        assert!(g.offer(id, "secret.pdf".into(), 100, MAX_CONCURRENT_FILES));
        assert!(
            !g.accepts_chunk(&id),
            "a pending (un-accepted) offer must not accept chunks"
        );
        // Accepting returns name+size so the caller can now open the disk sink.
        assert_eq!(g.accept(&id), Some(("secret.pdf".into(), 100)));
        assert!(g.accepts_chunk(&id), "an accepted transfer accepts chunks");
        g.finish(&id);
        assert!(
            !g.accepts_chunk(&id),
            "a finished transfer no longer accepts chunks"
        );
    }

    /// A rejected offer never becomes writable and can't be accepted afterwards.
    #[test]
    fn file_gate_reject_never_writes() {
        let mut g = FileGate::new();
        let id = [2u8; 16];
        g.offer(id, "x".into(), 1, MAX_CONCURRENT_FILES);
        g.reject(&id);
        assert!(
            !g.accepts_chunk(&id),
            "a rejected offer must never accept chunks"
        );
        assert_eq!(
            g.accept(&id),
            None,
            "a rejected offer cannot be accepted later"
        );
        assert!(!g.accepts_chunk(&id));
    }

    /// Chunks for a transfer that was never offered are refused (no accept, no id).
    #[test]
    fn file_gate_unknown_id_refused() {
        let mut g = FileGate::new();
        assert!(
            !g.accepts_chunk(&[9u8; 16]),
            "chunks for an unknown transfer are refused"
        );
        // Accepting an id that was never offered yields nothing to open.
        assert_eq!(g.accept(&[9u8; 16]), None);
    }

    /// The concurrency cap refuses further offers (no unbounded pending files).
    #[test]
    fn file_gate_caps_concurrent_offers() {
        let mut g = FileGate::new();
        for i in 0..3u8 {
            assert!(g.offer([i; 16], "f".into(), 1, 3));
        }
        assert!(
            !g.offer([99u8; 16], "f".into(), 1, 3),
            "beyond the cap, offers are refused"
        );
        assert_eq!(g.in_flight(), 3);
    }

    /// The disk-fill guard: a peer can't push past the size it offered, and the
    /// running total can't overflow. Pure — no filesystem touched.
    #[test]
    fn accept_total_caps_at_offered_size() {
        // Within the offer: fine, returns the new running total.
        assert_eq!(accept_total(0, 100, 512).unwrap(), 100);
        assert_eq!(accept_total(500, 12, 512).unwrap(), 512); // exactly fills
                                                              // One byte past the offer: refused.
        let err = accept_total(512, 1, 512).expect_err("must reject exceeding the offer");
        assert!(
            err.to_string().contains("more than the offered"),
            "got: {err}"
        );
        // A chunk that alone overshoots: refused.
        assert!(accept_total(0, 1000, 512).is_err());
        // Overflow of the running counter: refused, not wrapped.
        assert!(accept_total(u64::MAX, 1, u64::MAX).is_err());
    }
}
