//! FamChat Hub — a headless, always-on relay + mailbox for one family room.
//!
//! Every FamChat client opens a normal sealed channel to the hub (Noise,
//! authenticated by the family word). The hub is the trusted endpoint: it reads
//! each message, appends it to one ordered log, delivers it live to whoever is
//! connected, and holds it for anyone offline — replaying what they missed the
//! moment they reconnect. State is persisted so a restart doesn't lose the queue.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use famchat_core::{
    Auth, ClientMsg, Established, Frame, Link, SealedChannel, ServerMsg, TcpTransport, Transport,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

/// Hard cap on retained messages, so the log can't grow without bound even if a
/// member never comes back to acknowledge older ones. Plenty for a family.
const MAX_LOG: usize = 20_000;

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One stored message in the family room's ordered log.
#[derive(Serialize, Deserialize, Clone)]
struct LogEntry {
    seq: u64,
    from: String,
    name: String,
    text: String,
    ts: i64,
}

/// The durable state (persisted to disk).
#[derive(Serialize, Deserialize, Default)]
struct Persisted {
    next_seq: u64,
    log: Vec<LogEntry>,
    /// member id -> highest seq they've acknowledged.
    cursors: HashMap<String, u64>,
    /// member id -> latest display name.
    names: HashMap<String, String>,
}

/// Hub state: durable data plus the live push-channels for connected members.
pub struct Hub {
    p: Persisted,
    /// member id -> channel that pushes messages to their live connection.
    online: HashMap<String, mpsc::UnboundedSender<ServerMsg>>,
    path: PathBuf,
}

impl Hub {
    pub fn load(path: PathBuf) -> Self {
        let p = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Hub {
            p,
            online: HashMap::new(),
            path,
        }
    }

    /// Write durable state to disk atomically (temp file + rename).
    fn persist(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(s) = serde_json::to_string(&self.p) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, s).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    /// Keep the log bounded (drop the oldest beyond the cap).
    fn cap_log(&mut self) {
        if self.p.log.len() > MAX_LOG {
            let excess = self.p.log.len() - MAX_LOG;
            self.p.log.drain(0..excess);
        }
    }
}

/// Bind and serve forever: accept clients and hand each to a task. Never returns
/// under normal operation.
pub async fn run(bind: &str, word: String, data: PathBuf) {
    let hub = Arc::new(Mutex::new(Hub::load(data.clone())));
    let listener = match TcpTransport.listen(bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("famchat-hub: could not bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "famchat-hub: listening on {bind} · state at {}",
        data.display()
    );
    serve(listener, word, hub).await;
}

/// The accept loop, factored out so tests can drive it against an in-process hub.
pub async fn serve(listener: Box<dyn famchat_core::Listener>, word: String, hub: Arc<Mutex<Hub>>) {
    let mut link = Link::Listen {
        listener,
        auth: Auth::Code(word),
    };
    loop {
        match link.establish().await {
            Ok(est) => {
                let hub = hub.clone();
                tokio::spawn(handle_client(hub, est));
            }
            // A failed handshake just means keep waiting for the next client.
            Err(_) => continue,
        }
    }
}

/// Serve one connected client for the life of its connection.
async fn handle_client(hub: Arc<Mutex<Hub>>, est: Established) {
    let (sender, mut receiver) = match SealedChannel::establish(est).await {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // The first thing a client sends is Hello. Ignore anything else until we have
    // it; give up if the connection closes first.
    let (id, name) = loop {
        match receiver.recv().await {
            Some(Frame::Group(b)) => {
                if let Some(ClientMsg::Hello { id, name }) = ClientMsg::decode(&b) {
                    break (id, name);
                }
            }
            Some(_) => {}
            None => return,
        }
    };

    // Register as online and read back our cursor.
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();
    let cursor = {
        let mut h = hub.lock().await;
        h.p.names.insert(id.clone(), name.clone());
        h.online.insert(id.clone(), tx);
        h.persist();
        h.p.cursors.get(&id).copied().unwrap_or(0)
    };
    println!("famchat-hub: + {name} ({id}) online");

    // Welcome, then replay everything they missed (seq > cursor).
    if sender
        .send(Frame::Group(ServerMsg::Welcome.encode()))
        .await
        .is_err()
    {
        go_offline(&hub, &id).await;
        return;
    }
    let backlog: Vec<ServerMsg> = {
        let h = hub.lock().await;
        h.p.log
            .iter()
            .filter(|e| e.seq > cursor)
            .map(entry_to_msg)
            .collect()
    };
    for m in backlog {
        if sender.send(Frame::Group(m.encode())).await.is_err() {
            go_offline(&hub, &id).await;
            return;
        }
    }

    // Live loop: push queued messages out, and take in the client's sends/acks.
    loop {
        tokio::select! {
            Some(out) = rx.recv() => {
                if sender.send(Frame::Group(out.encode())).await.is_err() { break; }
            }
            frame = receiver.recv() => {
                match frame {
                    Some(Frame::Group(b)) => match ClientMsg::decode(&b) {
                        Some(ClientMsg::Send { text }) => handle_send(&hub, &id, &name, text).await,
                        Some(ClientMsg::Ack { seq }) => {
                            let mut h = hub.lock().await;
                            let c = h.p.cursors.entry(id.clone()).or_insert(0);
                            if seq > *c { *c = seq; }
                            h.persist();
                        }
                        _ => {}
                    },
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }

    go_offline(&hub, &id).await;
    println!("famchat-hub: - {name} ({id}) offline");
}

/// Append a new message, mark it delivered to its sender (they rendered it
/// locally), persist, and push it to every other member who is online.
async fn handle_send(hub: &Arc<Mutex<Hub>>, from_id: &str, from_name: &str, text: String) {
    let (msg, targets) = {
        let mut h = hub.lock().await;
        let seq = h.p.next_seq + 1;
        h.p.next_seq = seq;
        let ts = now_ts();
        h.p.log.push(LogEntry {
            seq,
            from: from_id.to_string(),
            name: from_name.to_string(),
            text: text.clone(),
            ts,
        });
        h.p.cursors.insert(from_id.to_string(), seq);
        h.cap_log();
        h.persist();
        let msg = ServerMsg::Msg {
            seq,
            from: from_id.to_string(),
            name: from_name.to_string(),
            text,
            ts,
        };
        let targets: Vec<_> = h
            .online
            .iter()
            .filter(|(mid, _)| mid.as_str() != from_id)
            .map(|(_, tx)| tx.clone())
            .collect();
        (msg, targets)
    };
    for tx in targets {
        let _ = tx.send(msg.clone());
    }
}

/// Remove this member's live push-channel (called when their connection ends).
async fn go_offline(hub: &Arc<Mutex<Hub>>, id: &str) {
    hub.lock().await.online.remove(id);
}

fn entry_to_msg(e: &LogEntry) -> ServerMsg {
    ServerMsg::Msg {
        seq: e.seq,
        from: e.from.clone(),
        name: e.name.clone(),
        text: e.text.clone(),
        ts: e.ts,
    }
}

/// Resolved runtime configuration.
pub struct Config {
    pub word: Option<String>,
    pub bind: String,
    pub data: PathBuf,
}

impl Config {
    pub fn from_env_and_args() -> Config {
        let mut word = std::env::var("FAMCHAT_HUB_WORD").ok();
        let mut bind =
            std::env::var("FAMCHAT_HUB_BIND").unwrap_or_else(|_| "0.0.0.0:9000".to_string());
        let mut data = std::env::var("FAMCHAT_HUB_DATA").ok().map(PathBuf::from);

        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--word" => word = args.next(),
                "--bind" => {
                    if let Some(v) = args.next() {
                        bind = v;
                    }
                }
                "--data" => data = args.next().map(PathBuf::from),
                _ => {}
            }
        }

        Config {
            word,
            bind,
            data: data.unwrap_or_else(default_data_path),
        }
    }
}

pub fn default_data_path() -> PathBuf {
    directories::ProjectDirs::from("", "nyfe", "famchat-hub")
        .map(|d| d.data_dir().join("hub.json"))
        .unwrap_or_else(|| PathBuf::from("famchat-hub.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use famchat_core::{SealedReceiver, SealedSender};
    use tokio::time::{timeout, Duration};

    async fn connect(
        addr: &str,
        word: &str,
        id: &str,
        name: &str,
    ) -> (SealedSender, SealedReceiver) {
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        let mut link = Link::Connect {
            transport,
            target: addr.to_string(),
            auth: Auth::Code(word.to_string()),
        };
        let est = link.establish().await.expect("client establishes");
        let (s, r) = SealedChannel::establish(est).await.expect("sealed channel");
        s.send(Frame::Group(
            ClientMsg::Hello {
                id: id.into(),
                name: name.into(),
            }
            .encode(),
        ))
        .await
        .expect("hello");
        (s, r)
    }

    /// Read frames until a `Msg` arrives (skipping Welcome), or time out.
    async fn next_msg_text(r: &mut SealedReceiver) -> Option<String> {
        let fut = async {
            loop {
                match r.recv().await {
                    Some(Frame::Group(b)) => {
                        if let Some(ServerMsg::Msg { text, .. }) = ServerMsg::decode(&b) {
                            return Some(text);
                        }
                    }
                    Some(_) => {}
                    None => return None,
                }
            }
        };
        timeout(Duration::from_secs(5), fut).await.ok().flatten()
    }

    /// Poll the hub's on-disk state until it contains `needle`, so the test waits
    /// on the hub actually processing a message rather than a fixed sleep.
    async fn wait_persisted(path: &std::path::Path, needle: &str) {
        let fut = async {
            loop {
                if std::fs::read_to_string(path)
                    .map(|s| s.contains(needle))
                    .unwrap_or(false)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        assert!(
            timeout(Duration::from_secs(5), fut).await.is_ok(),
            "hub did not persist {needle} in time"
        );
    }

    /// The core mailbox guarantee: a member who was OFFLINE when a message was sent
    /// receives it (from the backlog) the moment they connect.
    #[tokio::test]
    async fn offline_member_gets_backlog_on_reconnect() {
        let data =
            std::env::temp_dir().join(format!("famchat-hub-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&data);
        let hub = Arc::new(Mutex::new(Hub::load(data.clone())));

        let listener = TcpTransport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let word = "family-word".to_string();
        {
            let hub = hub.clone();
            let word = word.clone();
            tokio::spawn(async move { serve(listener, word, hub).await });
        }

        // Alice connects and sends a message while Bob is NOT connected.
        let (sa, mut ra) = connect(&addr, &word, "devA", "Alice").await;
        let _ = timeout(Duration::from_secs(5), ra.recv()).await; // consume Welcome
        sa.send(Frame::Group(
            ClientMsg::Send {
                text: "dinner at 6".into(),
            }
            .encode(),
        ))
        .await
        .unwrap();
        // Deterministically wait until the hub has logged + persisted it.
        wait_persisted(&data, "dinner at 6").await;

        // Bob connects later — he was offline when it was sent, but gets it now.
        let (_sb, mut rb) = connect(&addr, &word, "devB", "Bob").await;
        assert_eq!(next_msg_text(&mut rb).await.as_deref(), Some("dinner at 6"));

        drop(sa);
        let _ = std::fs::remove_file(&data);
    }

    /// A message sent while BOTH are online is delivered live to the other member
    /// (and not echoed back to its sender).
    #[tokio::test]
    async fn live_delivery_to_other_member() {
        let data =
            std::env::temp_dir().join(format!("famchat-hub-live-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&data);
        let hub = Arc::new(Mutex::new(Hub::load(data.clone())));
        let listener = TcpTransport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let word = "w".to_string();
        {
            let hub = hub.clone();
            let word = word.clone();
            tokio::spawn(async move { serve(listener, word, hub).await });
        }

        let (_sa, mut ra) = connect(&addr, &word, "devA", "Alice").await;
        let (sb, mut rb) = connect(&addr, &word, "devB", "Bob").await;
        // Drain welcomes — receiving Alice's Welcome proves she's registered online,
        // so Bob's message below reaches her live.
        let _ = timeout(Duration::from_secs(5), ra.recv()).await;
        let _ = timeout(Duration::from_secs(5), rb.recv()).await;

        sb.send(Frame::Group(
            ClientMsg::Send {
                text: "on my way".into(),
            }
            .encode(),
        ))
        .await
        .unwrap();
        // Alice (the other member) receives it live.
        assert_eq!(next_msg_text(&mut ra).await.as_deref(), Some("on my way"));

        let _ = std::fs::remove_file(&data);
    }
}
