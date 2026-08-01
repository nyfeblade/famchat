//! FamChat Hub — a small, always-on private chat server for one family.
//!
//! Clients open one sealed channel each (Noise, authenticated by the family word)
//! and sign in with a stable device id + name. Through that single connection the
//! hub carries the whole-family room, private DMs, and custom rooms — each its own
//! thread with its own ordered log and per-person cursor. Anyone offline is replayed
//! exactly what they missed the moment they reconnect. State persists across
//! restarts. The hub is trusted: it decrypts, stores, and routes.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use famchat_core::{
    dm_id, Auth, ClientMsg, ConvKind, ConvMeta, Established, Frame, Link, Member, SealedChannel,
    ServerMsg, TcpTransport, Transport, FAMILY_ROOM,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};

/// Push channel to one connected member's socket.
type Push = mpsc::UnboundedSender<ServerMsg>;

/// Hard per-conversation cap on retained messages.
const MAX_LOG: usize = 20_000;

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone)]
struct LogEntry {
    seq: u64,
    from: String,
    name: String,
    text: String,
    ts: i64,
}

/// One conversation (the family room, a DM, or a custom room).
#[derive(Serialize, Deserialize)]
struct Conv {
    kind: ConvKind,
    title: String,
    members: Vec<String>,
    #[serde(default)]
    log: Vec<LogEntry>,
    #[serde(default)]
    cursors: HashMap<String, u64>,
    #[serde(default)]
    next_seq: u64,
}

impl Conv {
    fn meta(&self, id: &str) -> ConvMeta {
        ConvMeta {
            id: id.to_string(),
            kind: self.kind,
            title: self.title.clone(),
            members: self.members.clone(),
        }
    }
    fn has(&self, member: &str) -> bool {
        self.members.iter().any(|m| m == member)
    }
}

/// Durable state persisted to disk.
#[derive(Serialize, Deserialize, Default)]
struct Persisted {
    /// member id -> display name (the family directory).
    #[serde(default)]
    members: HashMap<String, String>,
    /// conversation id -> conversation.
    #[serde(default)]
    convs: HashMap<String, Conv>,
}

/// Hub state: durable data plus live push-channels for connected members.
pub struct Hub {
    p: Persisted,
    online: HashMap<String, Push>,
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

    /// Make sure the whole-family room exists and includes `id`.
    fn ensure_family(&mut self, id: &str) {
        let fam = self
            .p
            .convs
            .entry(FAMILY_ROOM.to_string())
            .or_insert_with(|| Conv {
                kind: ConvKind::Room,
                title: "Family".into(),
                members: Vec::new(),
                log: Vec::new(),
                cursors: HashMap::new(),
                next_seq: 0,
            });
        if !fam.has(id) {
            fam.members.push(id.to_string());
        }
    }

    fn directory(&self) -> Vec<Member> {
        self.p
            .members
            .iter()
            .map(|(id, name)| Member {
                id: id.clone(),
                name: name.clone(),
            })
            .collect()
    }

    fn online_ids(&self) -> Vec<String> {
        self.online.keys().cloned().collect()
    }

    fn metas_for(&self, id: &str) -> Vec<ConvMeta> {
        self.p
            .convs
            .iter()
            .filter(|(_, c)| c.has(id))
            .map(|(cid, c)| c.meta(cid))
            .collect()
    }

    /// Everything `id` hasn't yet acknowledged, across every conversation they're in.
    fn backlog_for(&self, id: &str) -> Vec<ServerMsg> {
        let mut out = Vec::new();
        for (cid, c) in &self.p.convs {
            if !c.has(id) {
                continue;
            }
            let cur = c.cursors.get(id).copied().unwrap_or(0);
            for e in c.log.iter().filter(|e| e.seq > cur) {
                out.push(ServerMsg::Msg {
                    conv: cid.clone(),
                    seq: e.seq,
                    from: e.from.clone(),
                    name: e.name.clone(),
                    text: e.text.clone(),
                    ts: e.ts,
                });
            }
        }
        out
    }

    fn pushes_for(&self, ids: &[String], except: Option<&str>) -> Vec<Push> {
        ids.iter()
            .filter(|m| except.map_or(true, |ex| m.as_str() != ex))
            .filter_map(|m| self.online.get(m).cloned())
            .collect()
    }
}

/// Bind and serve forever.
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
            Err(_) => continue,
        }
    }
}

async fn handle_client(hub: Arc<Mutex<Hub>>, est: Established) {
    let (sender, mut receiver) = match SealedChannel::establish(est).await {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // Sign in.
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

    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (welcome, backlog, dir_targets, members_msg, presence_msg) = {
        let mut h = hub.lock().await;
        h.p.members.insert(id.clone(), name.clone());
        h.ensure_family(&id);
        h.online.insert(id.clone(), tx.clone());
        h.persist();
        let dir = h.directory();
        let online = h.online_ids();
        let welcome = ServerMsg::Welcome {
            you: id.clone(),
            members: dir.clone(),
            convs: h.metas_for(&id),
            online: online.clone(),
        };
        let backlog = h.backlog_for(&id);
        let dir_targets: Vec<Push> = h.online.values().cloned().collect();
        (
            welcome,
            backlog,
            dir_targets,
            ServerMsg::Members { members: dir },
            ServerMsg::Presence { online },
        )
    };

    if sender.send(Frame::Group(welcome.encode())).await.is_err() {
        go_offline(&hub, &id).await;
        return;
    }
    for m in backlog {
        if sender.send(Frame::Group(m.encode())).await.is_err() {
            go_offline(&hub, &id).await;
            return;
        }
    }
    // Tell everyone the directory + who's online changed.
    for t in &dir_targets {
        let _ = t.send(members_msg.clone());
        let _ = t.send(presence_msg.clone());
    }
    println!("famchat-hub: + {name} ({id}) online");

    loop {
        tokio::select! {
            Some(out) = rx.recv() => {
                if sender.send(Frame::Group(out.encode())).await.is_err() { break; }
            }
            frame = receiver.recv() => {
                match frame {
                    Some(Frame::Group(b)) => match ClientMsg::decode(&b) {
                        Some(ClientMsg::Send { conv, text }) => {
                            let out = { let mut h = hub.lock().await; do_send(&mut h, &id, &conv, text) };
                            if let Some((msg, targets)) = out {
                                for t in targets { let _ = t.send(msg.clone()); }
                            }
                        }
                        Some(ClientMsg::Ack { conv, seq }) => {
                            let mut h = hub.lock().await;
                            if let Some(c) = h.p.convs.get_mut(&conv) {
                                let cur = c.cursors.entry(id.clone()).or_insert(0);
                                if seq > *cur { *cur = seq; }
                            }
                            h.persist();
                        }
                        Some(ClientMsg::OpenDm { peer }) => {
                            let (meta, targets) = { let mut h = hub.lock().await; open_dm(&mut h, &id, &peer) };
                            let m = ServerMsg::Conv { meta };
                            for t in targets { let _ = t.send(m.clone()); }
                        }
                        Some(ClientMsg::CreateRoom { title, members }) => {
                            let (meta, targets) = { let mut h = hub.lock().await; create_room(&mut h, &id, title, members) };
                            let m = ServerMsg::Conv { meta };
                            for t in targets { let _ = t.send(m.clone()); }
                        }
                        Some(ClientMsg::Hello { .. }) | None => {}
                    },
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }

    // Offline: drop the push channel and tell everyone who's still online.
    let (targets, online) = {
        let mut h = hub.lock().await;
        h.online.remove(&id);
        let online = h.online_ids();
        (h.online.values().cloned().collect::<Vec<_>>(), online)
    };
    let pres = ServerMsg::Presence { online };
    for t in targets {
        let _ = t.send(pres.clone());
    }
    println!("famchat-hub: - {name} ({id}) offline");
}

/// Append a message to a conversation the sender belongs to, mark it delivered to
/// them, persist, and return the broadcast + the online recipients (minus sender).
fn do_send(h: &mut Hub, from_id: &str, conv: &str, text: String) -> Option<(ServerMsg, Vec<Push>)> {
    let name = h.p.members.get(from_id).cloned().unwrap_or_default();
    let (seq, ts, members) = {
        let c = h.p.convs.get_mut(conv)?;
        if !c.has(from_id) {
            return None;
        }
        let seq = c.next_seq + 1;
        c.next_seq = seq;
        let ts = now_ts();
        c.log.push(LogEntry {
            seq,
            from: from_id.to_string(),
            name: name.clone(),
            text: text.clone(),
            ts,
        });
        c.cursors.insert(from_id.to_string(), seq);
        if c.log.len() > MAX_LOG {
            let excess = c.log.len() - MAX_LOG;
            c.log.drain(0..excess);
        }
        (seq, ts, c.members.clone())
    };
    h.persist();
    let msg = ServerMsg::Msg {
        conv: conv.to_string(),
        seq,
        from: from_id.to_string(),
        name,
        text,
        ts,
    };
    let targets = h.pushes_for(&members, Some(from_id));
    Some((msg, targets))
}

/// Open (creating if needed) a DM between `id` and `peer`. Returns its meta and the
/// online members to notify.
fn open_dm(h: &mut Hub, id: &str, peer: &str) -> (ConvMeta, Vec<Push>) {
    let cid = dm_id(id, peer);
    if !h.p.convs.contains_key(&cid) {
        h.p.convs.insert(
            cid.clone(),
            Conv {
                kind: ConvKind::Dm,
                title: String::new(),
                members: vec![id.to_string(), peer.to_string()],
                log: Vec::new(),
                cursors: HashMap::new(),
                next_seq: 0,
            },
        );
        h.persist();
    }
    let c = &h.p.convs[&cid];
    let meta = c.meta(&cid);
    let targets = h.pushes_for(&meta.members, None);
    (meta, targets)
}

/// Create a named room with `id` plus the given members.
fn create_room(
    h: &mut Hub,
    id: &str,
    title: String,
    mut members: Vec<String>,
) -> (ConvMeta, Vec<Push>) {
    if !members.iter().any(|m| m == id) {
        members.push(id.to_string());
    }
    members.sort();
    members.dedup();
    let cid = format!("room:{}", famchat_core::new_conversation_id());
    h.p.convs.insert(
        cid.clone(),
        Conv {
            kind: ConvKind::Room,
            title: title.clone(),
            members: members.clone(),
            log: Vec::new(),
            cursors: HashMap::new(),
            next_seq: 0,
        },
    );
    h.persist();
    let meta = ConvMeta {
        id: cid,
        kind: ConvKind::Room,
        title,
        members: members.clone(),
    };
    let targets = h.pushes_for(&members, None);
    (meta, targets)
}

async fn go_offline(hub: &Arc<Mutex<Hub>>, id: &str) {
    hub.lock().await.online.remove(id);
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

    async fn send(s: &SealedSender, m: ClientMsg) {
        s.send(Frame::Group(m.encode())).await.unwrap();
    }

    async fn recv_sm(r: &mut SealedReceiver) -> Option<ServerMsg> {
        match r.recv().await {
            Some(Frame::Group(b)) => ServerMsg::decode(&b),
            _ => None,
        }
    }

    /// Read server messages until one matches `pred`, or time out.
    async fn wait_for<F: Fn(&ServerMsg) -> bool>(
        r: &mut SealedReceiver,
        pred: F,
    ) -> Option<ServerMsg> {
        let fut = async {
            loop {
                match recv_sm(r).await {
                    Some(m) => {
                        if pred(&m) {
                            return Some(m);
                        }
                    }
                    None => return None,
                }
            }
        };
        timeout(Duration::from_secs(5), fut).await.ok().flatten()
    }

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
            "not persisted: {needle}"
        );
    }

    async fn spawn_hub(word: &str) -> (String, std::path::PathBuf) {
        let data =
            std::env::temp_dir().join(format!("famchat-hub-{}-{}.json", word, std::process::id()));
        let _ = std::fs::remove_file(&data);
        let hub = Arc::new(Mutex::new(Hub::load(data.clone())));
        let listener = TcpTransport.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        let word = word.to_string();
        tokio::spawn(async move { serve(listener, word, hub).await });
        (addr, data)
    }

    /// The family room is a mailbox: a message sent while a member is offline is
    /// waiting for them when they sign in.
    #[tokio::test]
    async fn family_room_offline_backlog() {
        let (addr, data) = spawn_hub("famA").await;

        let (sa, mut ra) = connect(&addr, "famA", "dA", "Alice").await;
        wait_for(&mut ra, |m| matches!(m, ServerMsg::Welcome { .. }))
            .await
            .unwrap();
        send(
            &sa,
            ClientMsg::Send {
                conv: FAMILY_ROOM.into(),
                text: "dinner at 6".into(),
            },
        )
        .await;
        wait_persisted(&data, "dinner at 6").await;

        let (_sb, mut rb) = connect(&addr, "famA", "dB", "Bob").await;
        let got = wait_for(&mut rb, |m| {
            matches!(m, ServerMsg::Msg { conv, text, .. } if conv == FAMILY_ROOM && text == "dinner at 6")
        })
        .await;
        assert!(got.is_some(), "Bob should get the family-room backlog");

        let _ = std::fs::remove_file(&data);
    }

    /// A DM created + written while the other person is offline shows up as a
    /// conversation for them, with the message, when they sign in.
    #[tokio::test]
    async fn dm_is_created_and_delivered_offline() {
        let (addr, data) = spawn_hub("famB").await;

        let (sa, mut ra) = connect(&addr, "famB", "dA", "Alice").await;
        wait_for(&mut ra, |m| matches!(m, ServerMsg::Welcome { .. }))
            .await
            .unwrap();
        send(&sa, ClientMsg::OpenDm { peer: "dB".into() }).await;
        wait_for(&mut ra, |m| matches!(m, ServerMsg::Conv { .. }))
            .await
            .unwrap();
        let cid = dm_id("dA", "dB");
        send(
            &sa,
            ClientMsg::Send {
                conv: cid.clone(),
                text: "just you".into(),
            },
        )
        .await;
        wait_persisted(&data, "just you").await;

        // Bob signs in later: his Welcome lists the DM, and its message is delivered.
        let (_sb, mut rb) = connect(&addr, "famB", "dB", "Bob").await;
        let w = wait_for(&mut rb, |m| matches!(m, ServerMsg::Welcome { .. }))
            .await
            .unwrap();
        if let ServerMsg::Welcome { convs, .. } = w {
            assert!(
                convs.iter().any(|c| c.id == cid && c.kind == ConvKind::Dm),
                "Bob should see the DM"
            );
        }
        let got = wait_for(&mut rb, |m| {
            matches!(m, ServerMsg::Msg { conv, text, .. } if *conv == cid && text == "just you")
        })
        .await;
        assert!(got.is_some(), "Bob should receive the DM message he missed");

        let _ = std::fs::remove_file(&data);
    }
}
