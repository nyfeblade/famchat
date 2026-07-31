//! The networked group relay: a host that shuttles [`GroupMsg`]s between members
//! over their pairwise sealed channels, and the member client that drives its
//! [`GroupMember`] state machine against it.
//!
//! The host is a hub. Each member holds one pairwise [`SealedChannel`] to it. The
//! host learns the roster (who is present) and routes:
//! * `Hello` -> register the member, broadcast the updated `Roster` to everyone,
//! * `KeyFor{to,..}` -> forward the opaque sealed key blob to `to`,
//! * `Text{from,..}` -> broadcast the Sender-Key ciphertext to everyone else.
//!
//! The host never holds a Sender Key or a plaintext — `KeyFor` payloads are
//! sealed to each recipient and `Text` payloads are Sender-Key ciphertext. It is
//! trusted only for availability and membership, never confidentiality.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use tokio::sync::mpsc;

use crate::channel::SealedChannel;
use crate::groupsession::{GroupMember, GroupMsg, MemberId};
use crate::message::Frame;
use crate::session::{Established, Link};

/// A connected member as the host sees it: its public key and a channel to push
/// bytes toward it (drained by that member's writer task).
struct MemberConn {
    public: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
}

type Roster = Arc<Mutex<HashMap<MemberId, MemberConn>>>;

/// The group relay host.
pub struct GroupHost;

impl GroupHost {
    /// Run the relay: accept members forever and route between them. Runs until
    /// the listener errors unrecoverably. Spawn this as a task.
    pub async fn serve(mut link: Link) {
        let roster: Roster = Arc::new(Mutex::new(HashMap::new()));
        loop {
            let est = match link.establish().await {
                Ok(e) => e,
                Err(_) => continue,
            };
            let roster = roster.clone();
            tokio::spawn(async move {
                let (sender, receiver) = match SealedChannel::establish(est).await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                // Writer task: owns this member's sender, drains queued bytes.
                let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(128);
                tokio::spawn(async move {
                    while let Some(bytes) = out_rx.recv().await {
                        if sender.send(Frame::Group(bytes)).await.is_err() {
                            break;
                        }
                    }
                });
                host_reader(receiver, roster, out_tx).await;
            });
        }
    }
}

/// Read one member's incoming group messages and route them.
async fn host_reader(
    mut receiver: crate::channel::SealedReceiver,
    roster: Roster,
    out_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut my_id: Option<MemberId> = None;
    while let Some(frame) = receiver.recv().await {
        let Frame::Group(bytes) = frame else { continue };
        let Ok(msg) = GroupMsg::decode(&bytes) else {
            continue;
        };
        match msg {
            GroupMsg::Hello { id, public } => {
                my_id = Some(id);
                roster.lock().unwrap().insert(
                    id,
                    MemberConn {
                        public,
                        tx: out_tx.clone(),
                    },
                );
                broadcast_roster(&roster).await;
            }
            GroupMsg::KeyFor { to, from, sealed } => {
                let target = roster.lock().unwrap().get(&to).map(|c| c.tx.clone());
                if let Some(tx) = target {
                    let _ = tx
                        .send(GroupMsg::KeyFor { to, from, sealed }.encode())
                        .await;
                }
            }
            GroupMsg::Text { from, ct } => {
                let targets: Vec<mpsc::Sender<Vec<u8>>> = {
                    let r = roster.lock().unwrap();
                    r.iter()
                        .filter(|(id, _)| **id != from)
                        .map(|(_, c)| c.tx.clone())
                        .collect()
                };
                let enc = GroupMsg::Text { from, ct }.encode();
                for tx in targets {
                    let _ = tx.send(enc.clone()).await;
                }
            }
            // Members never originate a roster; ignore.
            GroupMsg::Roster { .. } => {}
        }
    }
    // Member left: drop it and let everyone else know.
    if let Some(id) = my_id {
        roster.lock().unwrap().remove(&id);
        broadcast_roster(&roster).await;
    }
}

/// Send the current roster to every connected member.
async fn broadcast_roster(roster: &Roster) {
    let (members, targets): (Vec<(MemberId, [u8; 32])>, Vec<mpsc::Sender<Vec<u8>>>) = {
        let r = roster.lock().unwrap();
        let members = r.iter().map(|(id, c)| (*id, c.public)).collect();
        let targets = r.values().map(|c| c.tx.clone()).collect();
        (members, targets)
    };
    let enc = GroupMsg::Roster { members }.encode();
    for tx in targets {
        let _ = tx.send(enc.clone()).await;
    }
}

/// The send half of a group membership. Cheap to clone/hold; a group send never
/// blocks on the receive path.
#[derive(Clone)]
pub struct GroupHandle {
    send_tx: mpsc::Sender<Vec<u8>>,
}

impl GroupHandle {
    /// Send a group text (broadcast to all members).
    pub async fn send(&self, text: Vec<u8>) -> Result<()> {
        self.send_tx
            .send(text)
            .await
            .map_err(|_| anyhow!("group channel closed"))
    }
}

/// The receive half: decrypted group text from any member.
pub struct GroupReceiver {
    recv_rx: mpsc::Receiver<(MemberId, Vec<u8>)>,
}

impl GroupReceiver {
    /// Receive the next decrypted group text (sender id, plaintext), or `None`
    /// once the group closes.
    pub async fn recv(&mut self) -> Option<(MemberId, Vec<u8>)> {
        self.recv_rx.recv().await
    }
}

/// A member's client-side handle to a group.
pub struct GroupClient;

impl GroupClient {
    /// Join a group over an established pairwise connection to the host. Drives
    /// the [`GroupMember`] state machine: announces, key exchange, and text.
    /// Returns a cloneable send handle and a receiver.
    pub async fn join(est: Established) -> Result<(GroupHandle, GroupReceiver)> {
        let (sender, mut receiver) = SealedChannel::establish(est).await?;
        let mut member = GroupMember::new();
        sender
            .send(Frame::Group(member.hello().encode()))
            .await
            .map_err(|e| anyhow!("group join failed: {e}"))?;

        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(64);
        let (recv_tx, recv_rx) = mpsc::channel::<(MemberId, Vec<u8>)>(64);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    frame = receiver.recv() => {
                        let bytes = match frame {
                            Some(Frame::Group(b)) => b,
                            Some(_) => continue,
                            None => break,
                        };
                        let Ok(msg) = GroupMsg::decode(&bytes) else { continue };
                        match msg {
                            GroupMsg::Roster { members } => {
                                for out in member.on_roster(&members) {
                                    let _ = sender.send(Frame::Group(out.encode())).await;
                                }
                            }
                            GroupMsg::KeyFor { from, sealed, .. } => {
                                let _ = member.on_key_for(from, &sealed);
                            }
                            GroupMsg::Text { from, ct } => {
                                if let Ok(pt) = member.on_text(from, &ct) {
                                    if recv_tx.send((from, pt)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            GroupMsg::Hello { .. } => {}
                        }
                    }
                    text = send_rx.recv() => {
                        match text {
                            Some(t) => {
                                let m = member.encrypt(&t);
                                let _ = sender.send(Frame::Group(m.encode())).await;
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Ok((GroupHandle { send_tx }, GroupReceiver { recv_rx }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Auth, Link};
    use crate::transport::{TcpTransport, Transport};
    use std::time::Duration;

    /// A real host relays between two real members: A's group text reaches B,
    /// decrypted, through the whole stack (sealed channels + host-blind relay).
    #[tokio::test]
    async fn group_relay_end_to_end() {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        let listener = transport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let host_link = Link::Listen {
            listener,
            auth: Auth::Code("room-word".into()),
        };
        tokio::spawn(GroupHost::serve(host_link));

        let join = |t: Arc<dyn Transport>, addr: String| async move {
            let mut link = Link::Connect {
                transport: t,
                target: addr,
                auth: Auth::Code("room-word".into()),
            };
            let est = link.establish().await.unwrap();
            GroupClient::join(est).await.unwrap()
        };

        let (a_tx, _a_rx) = join(transport.clone(), addr.clone()).await;
        let (_b_tx, mut b_rx) = join(transport.clone(), addr.clone()).await;

        // Resend A's text on a cadence so the assertion doesn't race key
        // distribution (constant-rate cover traffic paces every hop).
        tokio::spawn(async move {
            loop {
                let _ = a_tx.send(b"meet at the vault, 9pm".to_vec()).await;
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        });

        let (_from, msg) = tokio::time::timeout(Duration::from_secs(25), b_rx.recv())
            .await
            .expect("group recv timed out")
            .expect("group closed");
        assert_eq!(msg, b"meet at the vault, 9pm");
    }
}
