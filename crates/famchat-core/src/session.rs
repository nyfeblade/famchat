//! Connection lifecycle: establishing (and re-establishing) an authenticated,
//! encrypted link over whatever [`Transport`] was chosen.
//!
//! A [`Link`] produces an [`Established`] connection on demand. The driver
//! (e.g. the Tauri layer) calls `establish()` again whenever the link drops, so
//! both roles stay usable: a listener keeps accepting new peers, and a
//! connector retries until its peer is reachable. Authentication material (a
//! code word or an identity) is held in the link and reused across reconnects.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::time::timeout;

use crate::identity::{self, Identity};
use crate::transport::{AnyStream, Listener, Transport};
use crate::wire;

/// Maximum time one handshake may take before we abandon it. Defends the
/// listener against a peer that connects and then never speaks (a slowloris
/// stall): the whole handshake — SPAKE2 exchange, Noise messages, ratchet
/// bootstrap reads — must complete within this window or the connection is
/// dropped and the listener moves on.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How a link authenticates its peer.
pub enum Auth {
    /// Shared code word (SPAKE2 PAKE). Held in memory, reused on reconnect.
    Code(String),
    /// Long-term identity, optionally pinning the peer's fingerprint.
    Identity {
        id: Identity,
        expect: Option<String>,
    },
}

/// A connection endpoint that can be (re-)established on demand.
pub enum Link {
    /// We wait for peers. The listener is bound once and accepts repeatedly.
    Listen {
        listener: Box<dyn Listener>,
        auth: Auth,
    },
    /// We reach out to a peer, retrying until it answers.
    Connect {
        transport: Arc<dyn Transport>,
        target: String,
        auth: Auth,
    },
}

/// What we learned about a session once it authenticated — surfaced to the UI
/// so it can show the peer's fingerprint, the transport, and the trust state.
#[derive(Clone, Debug)]
pub struct SessionInfo {
    /// Transport label, e.g. "tcp" or "tor".
    pub transport: String,
    /// True if authenticated by shared code word (no long-term identity).
    pub code_word: bool,
    /// Our own fingerprint (identity mode only).
    pub my_fingerprint: Option<String>,
    /// The peer's fingerprint (identity mode only).
    pub peer_fingerprint: Option<String>,
    /// True if the peer's fingerprint was pinned and matched.
    pub pinned: bool,
}

/// A live, authenticated, encrypted connection ready to be driven.
pub struct Established {
    pub reader: ReadHalf<AnyStream>,
    pub writer: WriteHalf<AnyStream>,
    pub transport: snow::TransportState,
    /// The Double Ratchet root seed (Noise handshake hash).
    pub handshake_hash: [u8; 32],
    /// True if we were the Noise initiator (the connecting side); decides the
    /// Double Ratchet bootstrap role.
    pub is_initiator: bool,
    pub info: SessionInfo,
}

impl Link {
    pub fn is_listener(&self) -> bool {
        matches!(self, Link::Listen { .. })
    }

    /// A short line describing what we're waiting on, for the UI.
    pub fn status_line(&self) -> String {
        match self {
            Link::Listen { listener, .. } => {
                format!("waiting for a peer at {}…", listener.local_addr())
            }
            Link::Connect { target, .. } => format!("connecting to {target}…"),
        }
    }

    /// Produce the next live connection. Blocks until one is authenticated.
    pub async fn establish(&mut self) -> Result<Established> {
        match self {
            Link::Listen { listener, auth } => loop {
                // A bad or unauthenticated peer must not take the listener down;
                // drop it quietly and wait for the next connection.
                let mut stream = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                match timeout(
                    HANDSHAKE_TIMEOUT,
                    handshake(&mut stream, auth, true, listener.kind()),
                )
                .await
                {
                    Ok(Ok((transport, handshake_hash, info))) => {
                        let (reader, writer) = tokio::io::split(stream);
                        return Ok(Established {
                            reader,
                            writer,
                            transport,
                            handshake_hash,
                            is_initiator: false,
                            info,
                        });
                    }
                    // A handshake error, or a silent peer that timed out: drop it
                    // and keep listening for the next one.
                    _ => continue,
                }
            },
            Link::Connect {
                transport,
                target,
                auth,
            } => {
                let mut stream = dial_with_retry(transport.as_ref(), target).await?;
                let (ts, handshake_hash, info) = timeout(
                    HANDSHAKE_TIMEOUT,
                    handshake(&mut stream, auth, false, transport.kind()),
                )
                .await
                .map_err(|_| anyhow!("handshake timed out"))??;
                let (reader, writer) = tokio::io::split(stream);
                Ok(Established {
                    reader,
                    writer,
                    transport: ts,
                    handshake_hash,
                    is_initiator: true,
                    info,
                })
            }
        }
    }
}

/// Retry the dial (the peer may not be listening yet) with a gentle backoff,
/// giving up after a bounded number of attempts.
async fn dial_with_retry(transport: &dyn Transport, target: &str) -> Result<AnyStream> {
    let mut delay = Duration::from_millis(500);
    for _ in 0..60 {
        match transport.dial(target).await {
            Ok(s) => return Ok(s),
            Err(_) => {
                tokio::time::sleep(delay).await;
                if delay < Duration::from_secs(3) {
                    delay += Duration::from_millis(500);
                }
            }
        }
    }
    bail!("could not reach {target}")
}

fn normalize_fp(fp: &str) -> String {
    fp.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

/// Perform the appropriate handshake for the auth mode and return the transport
/// state plus the session info. Re-runs the fingerprint pin check on every
/// (re)connect, so a swapped key is caught even mid-session.
async fn handshake(
    stream: &mut AnyStream,
    auth: &Auth,
    responder: bool,
    kind: &str,
) -> Result<(snow::TransportState, [u8; 32], SessionInfo)> {
    match auth {
        Auth::Code(word) => {
            let session = if responder {
                wire::handshake_responder_code(stream, word).await?
            } else {
                wire::handshake_initiator_code(stream, word).await?
            };
            Ok((
                session.transport,
                session.handshake_hash,
                SessionInfo {
                    transport: kind.to_string(),
                    code_word: true,
                    my_fingerprint: None,
                    peer_fingerprint: None,
                    pinned: false,
                },
            ))
        }
        Auth::Identity { id, expect } => {
            let session = if responder {
                wire::handshake_responder(stream, id).await?
            } else {
                wire::handshake_initiator(stream, id).await?
            };
            let peer_fp = identity::fingerprint(&session.remote_static);
            if let Some(exp) = expect {
                if normalize_fp(&peer_fp) != normalize_fp(exp) {
                    bail!(
                        "peer fingerprint mismatch (expected {exp}, got {peer_fp}) — possible MITM"
                    );
                }
            }
            Ok((
                session.transport,
                session.handshake_hash,
                SessionInfo {
                    transport: kind.to_string(),
                    code_word: false,
                    my_fingerprint: Some(identity::fingerprint(&id.public)),
                    peer_fingerprint: Some(peer_fp),
                    pinned: expect.is_some(),
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TcpTransport;

    /// End to end over the real Transport abstraction: a code-word listener must
    /// serve peers one after another, and each peer must authenticate through
    /// the type-erased stream. This exercises the exact establish() path the UI
    /// uses, including the stay-listening loop.
    #[tokio::test]
    async fn listener_serves_sequential_peers() {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let mut server = Link::Listen {
            listener,
            auth: Auth::Code("shared-word".into()),
        };

        for peer in 0..2 {
            let addr = addr.clone();
            let t2 = transport.clone();
            let client = tokio::spawn(async move {
                let mut c = Link::Connect {
                    transport: t2,
                    target: addr,
                    auth: Auth::Code("shared-word".into()),
                };
                c.establish().await.is_ok()
            });

            let est = server.establish().await;
            assert!(est.is_ok(), "listener should serve peer #{peer}");
            let est = est.unwrap();
            assert_eq!(est.info.transport, "tcp");
            assert!(est.info.code_word);
            drop(est); // peer's turn ends, connection closes

            assert!(client.await.unwrap(), "client #{peer} should connect");
        }
    }
}
