// FamChat desktop shell (Tauri 2). A simple, private chat for your home network:
// host a room or join one over the LAN with a shared family word, and messages are
// end-to-end encrypted in flight. No Tor, no accounts, no server — just a chat app
// for the people on your Wi-Fi.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Tripwire: `forbid` can't be locally overridden, so the build fails if any
// `unsafe` is added to the desktop shell. The app is safe Rust end to end.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use famchat_core::{
    human_size, Auth, ClientMsg, ConversationSummary, FileGate, Frame, GroupClient, GroupHandle,
    GroupHost, GroupReceiver, History, Incoming, Link, Listener, SealedChannel, SealedSender,
    ServerMsg, StoredMessage, TcpTransport, Transport, CHUNK_SIZE, MAX_CONCURRENT_FILES,
    MAX_FILE_SIZE,
};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex;

/// Shared app state: the active send channel(s), the always-open plaintext history
/// store, which conversation is active, and the handles of the background
/// receive/relay tasks so leaving a chat can actually stop them.
#[derive(Default)]
struct ChatState {
    sender: Mutex<Option<SealedSender>>,
    group: Mutex<Option<GroupHandle>>,
    /// The on-disk transcript. Opened once at startup (no passphrase) and kept open.
    history: Mutex<Option<History>>,
    /// The conversation currently being written to.
    active: Mutex<Option<Active>>,
    /// Join handles for the detached pump/relay tasks (drive, drive_group,
    /// GroupHost::serve). Leaving a chat aborts them so their receivers drop.
    tasks: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    /// Lets the `file_accept` / `file_reject` commands signal the active `drive`
    /// task's decision on an incoming file offer `(id, accepted)`. Incoming files
    /// are NOT written to disk until the user accepts (consent gate).
    file_decisions: Mutex<Option<tokio::sync::mpsc::UnboundedSender<([u8; 16], bool)>>>,
    /// When connected to a family hub, client messages (send / open-dm /
    /// create-room) are handed to the persistent hub task through this channel
    /// (Some => a hub connection is active).
    hub_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<ClientMsg>>>,
}

/// The conversation currently being written to. FamChat always keeps history, so
/// this is set whenever you're in a chat.
struct Active {
    id: String,
    title: String,
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Mark the active conversation for message persistence.
///
/// The conversation id is derived from the name so that re-joining a room with the
/// same name *continues the same transcript* (exactly what you want for a standing
/// family room), instead of starting a fresh one each time. If no name was given,
/// fall back to the address.
async fn set_active(app: &AppHandle, name: &str, fallback: &str) {
    let title = if name.trim().is_empty() {
        fallback.to_string()
    } else {
        name.trim().to_string()
    };
    let id = title.to_lowercase();
    *app.state::<ChatState>().active.lock().await = Some(Active { id, title });
}

/// The active conversation's (id, title) for the UI sidebar.
async fn active_ids(app: &AppHandle) -> (Option<String>, Option<String>) {
    let st = app.state::<ChatState>();
    let guard = st.active.lock().await;
    match guard.as_ref() {
        Some(a) => (Some(a.id.clone()), Some(a.title.clone())),
        None => (None, None),
    }
}

/// Append a message to the active conversation's transcript.
async fn persist_msg(app: &AppHandle, from: &str, text: &str, incoming: bool) {
    let st = app.state::<ChatState>();
    let (id, title) = match st.active.lock().await.as_ref() {
        Some(a) => (a.id.clone(), a.title.clone()),
        None => return,
    };
    let mut guard = st.history.lock().await;
    if let Some(h) = guard.as_mut() {
        let _ = h.append(
            &id,
            &title,
            StoredMessage {
                from: from.to_string(),
                text: text.to_string(),
                ts: now_ts(),
                incoming,
            },
        );
    }
}

/// Record a background pump/relay task handle so leaving a chat can abort it.
async fn track(app: &AppHandle, handle: tauri::async_runtime::JoinHandle<()>) {
    app.state::<ChatState>().tasks.lock().await.push(handle);
}

/// End the live session and clear its in-memory state. The transcript on disk is
/// kept (this is a "leave", not a "delete"). Idempotent.
async fn teardown_session(app: &AppHandle) {
    app.state::<ChatState>().clear().await;
}

impl ChatState {
    /// Clear all live-session state — factored out so it's unit-testable without a
    /// Tauri app. Aborts and drains every background task, drops the send handles,
    /// and forgets the active conversation. The on-disk transcript is untouched.
    async fn clear(&self) {
        for t in self.tasks.lock().await.drain(..) {
            t.abort();
        }
        *self.sender.lock().await = None;
        *self.group.lock().await = None;
        *self.active.lock().await = None;
        *self.file_decisions.lock().await = None;
        *self.hub_tx.lock().await = None;
    }
}

/// Leave the current conversation: tear the live session down but keep the saved
/// transcript. Fails closed — even if a handle was already gone, state is cleared.
#[tauri::command]
async fn disconnect(app: AppHandle) {
    teardown_session(&app).await;
    let _ = app.emit("status", json!({ "state": "disconnected" }));
}

/// App version, surfaced in the UI.
#[tauri::command]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Whether this build can install an in-app update in place. On Linux the Tauri
/// updater can only replace an AppImage — a `.deb`/`.rpm` or a loose binary can't
/// self-install, so we must NOT attempt it (doing so overwrites the app with the
/// AppImage and breaks it). On macOS the build is unsigned, so self-replacement is
/// unreliable and can fail read-only ("error 30"); we don't attempt it there either.
/// When this is false the UI points to the download page instead. Windows self-updates.
#[tauri::command]
fn can_self_update() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("APPIMAGE").is_some()
    }
    #[cfg(target_os = "macos")]
    {
        // FamChat's macOS build is unsigned (no Apple Developer account), so replacing
        // the .app in place is unreliable — depending on how macOS launched it, the swap
        // can land on a read-only location and fail with EROFS ("error 30"), even from
        // /Applications. So we never self-install on macOS: the app still checks for and
        // announces updates, but sends you to the download page to grab the new .dmg.
        // Reliable, and it never leaves the app half-updated.
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        true
    }
}

/// Open a URL in the user's default browser. Used to send people to the download
/// page when the app can't self-update (see `can_self_update`).
#[tauri::command]
fn open_url(url: String) {
    // Only ever called with our own https download page.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
}

/// Durable prefs (device identity + saved hub) read from the OS config dir. These
/// live on disk beside the transcript — outside the app bundle — so a reinstall
/// keeps your identity and reconnects you to your rooms.
#[tauri::command]
fn get_prefs() -> Result<famchat_core::Prefs, String> {
    famchat_core::prefs::load().map_err(|e| e.to_string())
}

/// Persist the hub connection so the next launch reconnects automatically.
#[tauri::command]
fn save_hub_prefs(
    address: String,
    word: String,
    name: String,
) -> Result<famchat_core::Prefs, String> {
    famchat_core::prefs::save_hub(&address, &word, &name).map_err(|e| e.to_string())
}

/// Forget the saved hub (keeps the device identity).
#[tauri::command]
fn clear_hub_prefs() -> Result<(), String> {
    famchat_core::prefs::clear_hub().map_err(|e| e.to_string())
}

/// All saved conversations, most-recently-active first, for the sidebar.
#[tauri::command]
async fn list_conversations(app: AppHandle) -> Result<Vec<ConversationSummary>, String> {
    let st = app.state::<ChatState>();
    let mut guard = st.history.lock().await;
    if guard.is_none() {
        *guard = Some(History::open().map_err(|e| e.to_string())?);
    }
    Ok(guard.as_ref().map(|h| h.summaries()).unwrap_or_default())
}

/// Load the stored messages of one saved conversation.
#[tauri::command]
async fn load_conversation(app: AppHandle, id: String) -> Result<Vec<StoredMessage>, String> {
    let st = app.state::<ChatState>();
    let guard = st.history.lock().await;
    Ok(guard.as_ref().map(|h| h.messages(&id)).unwrap_or_default())
}

/// Permanently delete every saved conversation on this device, then reopen a fresh
/// empty transcript. Irreversible — surfaced only from Settings behind a confirm.
#[tauri::command]
async fn clear_history(app: AppHandle) -> Result<(), String> {
    teardown_session(&app).await;
    famchat_core::history::delete().map_err(|e| e.to_string())?;
    *app.state::<ChatState>().history.lock().await =
        Some(History::open().map_err(|e| e.to_string())?);
    Ok(())
}

/// Turn an address into a dial target, defaulting to port 9000.
fn normalize_target(address: &str) -> String {
    if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:9000")
    }
}

/// The one and only transport: a direct LAN TCP socket.
fn build_transport() -> Arc<dyn Transport> {
    Arc::new(TcpTransport)
}

/// Bind a LAN listener (all interfaces, port 9000 by default).
async fn build_listener(bind: &str) -> Result<Box<dyn Listener>, String> {
    let bind = if bind.trim().is_empty() {
        "0.0.0.0:9000"
    } else {
        bind
    };
    TcpTransport.listen(bind).await.map_err(|e| e.to_string())
}

/// Start hosting a 2-person chat: bind on the LAN, wait for someone who knows the
/// family word, and open a sealed channel. Returns the address to share.
#[tauri::command]
async fn host(app: AppHandle, bind: String, code: String, name: String) -> Result<String, String> {
    let listener = build_listener(&bind).await?;
    // Rewrite the wildcard bind ("0.0.0.0:PORT") to this machine's LAN IP so the
    // address is actually dialable by another device on the network.
    let address = shareable_tcp_addr(&listener.local_addr());
    set_active(&app, &name, &address).await;
    let _ = app.emit(
        "status",
        json!({ "state": "listening", "address": address, "transport": "tcp", "reachable": true }),
    );
    let mut link = Link::Listen {
        listener,
        auth: Auth::Code(code),
    };
    let app2 = app.clone();
    let handle = tauri::async_runtime::spawn(async move {
        drive(app2, link_establish(&mut link).await).await;
    });
    track(&app, handle).await;
    Ok(address)
}

/// Join a 2-person chat at `address` using the shared family word.
#[tauri::command]
async fn connect(
    app: AppHandle,
    address: String,
    code: String,
    name: String,
) -> Result<(), String> {
    let target = normalize_target(&address);
    set_active(&app, &name, &target).await;
    let _ = app.emit(
        "status",
        json!({ "state": "connecting", "address": target, "transport": "tcp" }),
    );
    let mut link = Link::Connect {
        transport: build_transport(),
        target,
        auth: Auth::Code(code),
    };
    let app2 = app.clone();
    let handle = tauri::async_runtime::spawn(async move {
        drive(app2, link_establish(&mut link).await).await;
    });
    track(&app, handle).await;
    Ok(())
}

/// Send a text message over the active sealed channel (group or 2-party).
#[tauri::command]
async fn send_message(app: AppHandle, text: String) -> Result<(), String> {
    let st = app.state::<ChatState>();
    // A live group takes precedence over a 2-party channel. (Family-hub sends go
    // through `hub_send`, which targets a specific conversation.)
    {
        let g = st.group.lock().await;
        if let Some(handle) = g.as_ref() {
            handle
                .send(text.clone().into_bytes())
                .await
                .map_err(|e| e.to_string())?;
            let _ = app.emit("message", json!({ "text": text, "incoming": false }));
            persist_msg(&app, "You", &text, false).await;
            return Ok(());
        }
    }
    {
        let guard = st.sender.lock().await;
        match guard.as_ref() {
            Some(s) => s
                .send(Frame::Text(text.clone()))
                .await
                .map_err(|e| e.to_string())?,
            None => return Err("not connected".into()),
        }
    }
    let _ = app.emit("message", json!({ "text": text, "incoming": false }));
    persist_msg(&app, "You", &text, false).await;
    Ok(())
}

/// Sign in to a family hub (a private chat server on an always-on machine). The
/// connection is persistent and auto-reconnects. The hub carries every conversation
/// — the family room, DMs, and rooms — which the UI drives via the `hub` events and
/// the `hub_send` / `hub_open_dm` / `hub_create_room` commands.
#[tauri::command]
async fn connect_hub(
    app: AppHandle,
    address: String,
    code: String,
    name: String,
    id: String,
) -> Result<(), String> {
    let target = normalize_target(&address);
    let _ = app.emit(
        "status",
        json!({ "state": "connecting", "address": target, "transport": "hub" }),
    );
    let app2 = app.clone();
    let handle = tauri::async_runtime::spawn(async move {
        drive_hub(app2, target, code, id, name).await;
    });
    track(&app, handle).await;
    Ok(())
}

/// Hand a client message (send / open-dm / create-room) to the live hub task.
async fn push_hub(app: &AppHandle, msg: ClientMsg) -> Result<(), String> {
    let st = app.state::<ChatState>();
    let tx = st.hub_tx.lock().await;
    match tx.as_ref() {
        Some(tx) => tx
            .send(msg)
            .map_err(|_| "the hub connection is down".to_string()),
        None => Err("not connected to a hub".into()),
    }
}

/// Post a message to a hub conversation.
#[tauri::command]
async fn hub_send(app: AppHandle, conv: String, text: String) -> Result<(), String> {
    push_hub(&app, ClientMsg::Send { conv, text }).await
}

/// Open (or create) a private 1-on-1 with a person.
#[tauri::command]
async fn hub_open_dm(app: AppHandle, peer: String) -> Result<(), String> {
    push_hub(&app, ClientMsg::OpenDm { peer }).await
}

/// Create a named room with the given members.
#[tauri::command]
async fn hub_create_room(
    app: AppHandle,
    title: String,
    members: Vec<String>,
) -> Result<(), String> {
    push_hub(&app, ClientMsg::CreateRoom { title, members }).await
}

/// Forward one server message to the UI as a `hub` event, deduping message re-sends
/// (by conversation) so a reconnect within a session doesn't double up.
fn emit_hub(app: &AppHandle, sm: ServerMsg, last_seq: &mut HashMap<String, u64>) {
    if let ServerMsg::Msg { ref conv, seq, .. } = sm {
        let cur = last_seq.entry(conv.clone()).or_insert(0);
        if seq <= *cur {
            return;
        }
        *cur = seq;
    }
    let _ = app.emit("hub", sm);
}

/// Maintain a persistent connection to the hub: (re)connect, say Hello, then pump
/// outgoing client messages and forward incoming server messages to the UI. Loops
/// until the task is aborted by a teardown, reconnecting after a short pause.
async fn drive_hub(
    app: AppHandle,
    target: String,
    code: String,
    device_id: String,
    my_name: String,
) {
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<ClientMsg>();
    *app.state::<ChatState>().hub_tx.lock().await = Some(out_tx);
    // Per-conversation high-water mark, to dedup re-sent messages across reconnects.
    let mut last_seq: HashMap<String, u64> = HashMap::new();

    loop {
        let mut link = Link::Connect {
            transport: build_transport(),
            target: target.clone(),
            auth: Auth::Code(code.clone()),
        };
        let est = match link.establish().await {
            Ok(e) => e,
            Err(e) => {
                let _ = app.emit(
                    "status",
                    json!({ "state": "error", "detail": e.to_string() }),
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
        };
        let (sender, mut receiver) = match SealedChannel::establish(est).await {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
        };

        let _ = sender
            .send(Frame::Group(
                ClientMsg::Hello {
                    id: device_id.clone(),
                    name: my_name.clone(),
                }
                .encode(),
            ))
            .await;
        let _ = app.emit(
            "status",
            json!({ "state": "connected", "transport": "hub" }),
        );

        loop {
            tokio::select! {
                Some(cm) = out_rx.recv() => {
                    if sender.send(Frame::Group(cm.encode())).await.is_err() { break; }
                }
                frame = receiver.recv() => {
                    match frame {
                        Some(Frame::Group(b)) => {
                            if let Some(sm) = ServerMsg::decode(&b) {
                                emit_hub(&app, sm, &mut last_seq);
                            }
                        }
                        Some(_) => {}
                        None => break, // link dropped — reconnect
                    }
                }
            }
        }

        let _ = app.emit(
            "status",
            json!({ "state": "connecting", "transport": "hub", "reconnecting": true }),
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// A random 16-byte file-transfer id (reuses the vetted 128-bit id generator).
fn new_transfer_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    if let Ok(b) = hex::decode(famchat_core::new_conversation_id()) {
        if b.len() == 16 {
            id.copy_from_slice(&b);
        }
    }
    id
}

/// Parse a hex transfer id back into 16 bytes.
fn parse_transfer_id(s: &str) -> Result<[u8; 16], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    if b.len() != 16 {
        return Err("bad transfer id".into());
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&b);
    Ok(id)
}

/// Send one typed frame over the active 2-party sealed channel. File transfer is
/// 2-party only for now (the group byte-channel carries plain text), so we refuse
/// rather than silently mis-route a file into a group.
async fn send_frame_2party(app: &AppHandle, frame: Frame) -> Result<(), String> {
    let st = app.state::<ChatState>();
    if st.group.lock().await.is_some() {
        return Err("File sending isn't available in group chats yet.".into());
    }
    let guard = st.sender.lock().await;
    match guard.as_ref() {
        Some(s) => s.send(frame).await.map_err(|e| e.to_string()),
        None => Err("not connected".into()),
    }
}

/// Begin sending a file: emit the `FileOffer` and return the transfer id.
#[tauri::command]
async fn file_begin(app: AppHandle, name: String, size: u64) -> Result<String, String> {
    if size > MAX_FILE_SIZE {
        return Err(format!(
            "File is too large (max {}).",
            human_size(MAX_FILE_SIZE)
        ));
    }
    let id = new_transfer_id();
    send_frame_2party(
        &app,
        Frame::FileOffer {
            id,
            name: name.clone(),
            size,
        },
    )
    .await?;
    let hex_id = hex::encode(id);
    let _ = app.emit(
        "file",
        json!({ "event": "offer", "id": hex_id, "name": name, "size": size,
                "human": human_size(size), "incoming": false }),
    );
    persist_msg(
        &app,
        "You",
        &format!("📎 {name} ({})", human_size(size)),
        false,
    )
    .await;
    Ok(hex_id)
}

/// Stream one file chunk (hex-encoded so the byte payload survives the JSON IPC).
#[tauri::command]
async fn file_chunk(app: AppHandle, id: String, data_hex: String) -> Result<(), String> {
    let id = parse_transfer_id(&id)?;
    let data = hex::decode(&data_hex).map_err(|e| e.to_string())?;
    if data.len() > CHUNK_SIZE {
        return Err("chunk exceeds the maximum size".into());
    }
    send_frame_2party(&app, Frame::FileChunk { id, data }).await
}

/// Finish a file send: emit `FileEnd` so the peer flushes and closes the file.
#[tauri::command]
async fn file_end(app: AppHandle, id: String) -> Result<(), String> {
    let idb = parse_transfer_id(&id)?;
    send_frame_2party(&app, Frame::FileEnd { id: idb }).await?;
    let _ = app.emit("file", json!({ "event": "sent", "id": id }));
    Ok(())
}

/// Accept an incoming file offer: signal our receive task to open the destination
/// (so it exists before the peer's first chunk), then tell the peer it may stream.
#[tauri::command]
async fn file_accept(app: AppHandle, id: String) -> Result<(), String> {
    let idb = parse_transfer_id(&id)?;
    let st = app.state::<ChatState>();
    if let Some(tx) = st.file_decisions.lock().await.as_ref() {
        let _ = tx.send((idb, true));
    }
    send_frame_2party(&app, Frame::FileAccept { id: idb }).await
}

/// Decline an incoming file offer: nothing is ever written to disk.
#[tauri::command]
async fn file_reject(app: AppHandle, id: String) -> Result<(), String> {
    let idb = parse_transfer_id(&id)?;
    let st = app.state::<ChatState>();
    if let Some(tx) = st.file_decisions.lock().await.as_ref() {
        let _ = tx.send((idb, false));
    }
    send_frame_2party(&app, Frame::FileReject { id: idb }).await
}

/// Host a group room: run the relay and join it ourselves so the host can chat too.
/// Returns the invite address to share with the family.
#[tauri::command]
async fn host_group(
    app: AppHandle,
    bind: String,
    code: String,
    name: String,
) -> Result<String, String> {
    let listener = build_listener(&bind).await?;
    let raw_addr = listener.local_addr();
    let address = shareable_tcp_addr(&raw_addr);
    set_active(&app, &name, &address).await;
    let _ = app.emit(
        "status",
        json!({ "state": "listening", "address": address, "transport": "tcp", "group": true, "reachable": true }),
    );
    // The relay itself.
    let serve_handle = tauri::async_runtime::spawn(GroupHost::serve(Link::Listen {
        listener,
        auth: Auth::Code(code.clone()),
    }));
    track(&app, serve_handle).await;
    // Join our own relay over loopback so we participate too.
    let link = Link::Connect {
        transport: build_transport(),
        target: self_loopback(&raw_addr),
        auth: Auth::Code(code),
    };
    let member_handle = spawn_group_member(&app, link);
    track(&app, member_handle).await;
    Ok(address)
}

/// Join an existing group room at `address`.
#[tauri::command]
async fn join_group(
    app: AppHandle,
    address: String,
    code: String,
    name: String,
) -> Result<(), String> {
    let target = normalize_target(&address);
    set_active(&app, &name, &target).await;
    let _ = app.emit(
        "status",
        json!({ "state": "connecting", "address": target, "transport": "tcp", "group": true }),
    );
    let link = Link::Connect {
        transport: build_transport(),
        target,
        auth: Auth::Code(code),
    };
    let member_handle = spawn_group_member(&app, link);
    track(&app, member_handle).await;
    Ok(())
}

/// Rewrite a bind address (e.g. "0.0.0.0:PORT") into a loopback dial target.
fn self_loopback(bind_addr: &str) -> String {
    match bind_addr.rsplit_once(':') {
        Some((_, port)) => format!("127.0.0.1:{port}"),
        None => bind_addr.to_string(),
    }
}

/// This machine's primary LAN IPv4, or `None`. Uses the connected-UDP trick:
/// connecting a UDP socket sends no packets, it just makes the OS pick the egress
/// interface, whose local address is then the machine's LAN IP.
fn lan_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

/// Turn a wildcard bind ("0.0.0.0:PORT") into a *shareable* LAN address, keeping the
/// port. Falls back to the raw address if no LAN IP is found.
fn shareable_tcp_addr(raw: &str) -> String {
    let port = raw.rsplit(':').next().unwrap_or("9000");
    match lan_ipv4() {
        Some(ip) => format!("{ip}:{port}"),
        None => raw.to_string(),
    }
}

/// Establish a group membership over `link` in the background, store the send
/// handle, and pump received group text to the UI.
fn spawn_group_member(app: &AppHandle, mut link: Link) -> tauri::async_runtime::JoinHandle<()> {
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let est = match link.establish().await {
            Ok(e) => e,
            Err(e) => {
                let _ = app2.emit(
                    "status",
                    json!({ "state": "error", "detail": e.to_string() }),
                );
                return;
            }
        };
        match GroupClient::join(est).await {
            Ok((handle, receiver)) => {
                {
                    *app2.state::<ChatState>().group.lock().await = Some(handle);
                }
                drive_group(app2, receiver).await;
            }
            Err(e) => {
                let _ = app2.emit(
                    "status",
                    json!({ "state": "error", "detail": e.to_string() }),
                );
            }
        }
    })
}

/// Deliver received group text to the UI until the group closes.
async fn drive_group(app: AppHandle, mut receiver: GroupReceiver) {
    let (conv_id, conv_title) = active_ids(&app).await;
    let room = conv_title.clone().unwrap_or_else(|| "Family".to_string());
    let _ = app.emit(
        "status",
        json!({
            "state": "connected",
            "transport": "group",
            "code_word": true,
            "conversation_id": conv_id,
            "conversation_title": conv_title,
        }),
    );
    while let Some((_from, bytes)) = receiver.recv().await {
        let text = String::from_utf8_lossy(&bytes).to_string();
        // Sender display names aren't in the group protocol yet, so incoming group
        // messages are labelled with the room name.
        let _ = app.emit(
            "message",
            json!({ "text": text, "incoming": true, "from": room }),
        );
        persist_msg(&app, &room, &text, true).await;
    }
    {
        *app.state::<ChatState>().group.lock().await = None;
    }
    let _ = app.emit("status", json!({ "state": "disconnected" }));
}

/// Helper: run establish() on a link, mapping the error to a String.
async fn link_establish(link: &mut Link) -> Result<famchat_core::session::Established, String> {
    link.establish().await.map_err(|e| e.to_string())
}

/// Given an established connection (or an error), open the sealed channel, store
/// the sender, emit `connected`, and pump incoming messages until it closes.
async fn drive(app: AppHandle, established: Result<famchat_core::session::Established, String>) {
    let est = match established {
        Ok(e) => e,
        Err(detail) => {
            let _ = app.emit("status", json!({ "state": "error", "detail": detail }));
            return;
        }
    };
    let (sender, mut receiver) = match SealedChannel::establish(est).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = app.emit(
                "status",
                json!({ "state": "error", "detail": e.to_string() }),
            );
            return;
        }
    };

    {
        *app.state::<ChatState>().sender.lock().await = Some(sender);
    }

    let info = receiver.info().clone();
    let (conv_id, conv_title) = active_ids(&app).await;
    let peer_label = conv_title.clone().unwrap_or_else(|| "Someone".to_string());
    let _ = app.emit(
        "status",
        json!({
            "state": "connected",
            "transport": info.transport,
            "code_word": info.code_word,
            "conversation_id": conv_id,
            "conversation_title": conv_title,
        }),
    );

    // Inbound file transfers. CONSENT GATE: nothing is written to disk until the
    // user accepts. `gate` (the engine's unit-tested `FileGate`) decides whether
    // bytes are allowed; `sinks` holds the open disk handle for each accepted
    // transfer. Leaving the chat aborts this task, dropping every partial handle.
    let mut gate = FileGate::new();
    let mut sinks: HashMap<[u8; 16], Incoming> = HashMap::new();

    let (dec_tx, mut dec_rx) = tokio::sync::mpsc::unbounded_channel::<([u8; 16], bool)>();
    *app.state::<ChatState>().file_decisions.lock().await = Some(dec_tx);

    loop {
        tokio::select! {
            Some((id, accepted)) = dec_rx.recv() => {
                if accepted {
                    if let Some((name, size)) = gate.accept(&id) {
                        match Incoming::start(&name, size) {
                            Ok(inc) => {
                                sinks.insert(id, inc);
                                let _ = app.emit("file", json!({ "event": "accepted", "id": hex::encode(id) }));
                            }
                            Err(e) => {
                                gate.finish(&id);
                                let _ = app.emit("file", json!({ "event": "error", "id": hex::encode(id), "detail": e.to_string() }));
                            }
                        }
                    }
                } else {
                    gate.reject(&id);
                    let _ = app.emit("file", json!({ "event": "declined", "id": hex::encode(id) }));
                }
            }
            frame = receiver.recv() => {
                let Some(frame) = frame else { break };
                match frame {
                    Frame::Text(t) => {
                        let _ = app.emit("message", json!({ "text": t, "incoming": true, "from": peer_label }));
                        persist_msg(&app, &peer_label, &t, true).await;
                    }
                    Frame::FileOffer { id, name, size } => {
                        if gate.offer(id, name.clone(), size, MAX_CONCURRENT_FILES) {
                            let _ = app.emit("file", json!({ "event": "offer", "id": hex::encode(id),
                                "name": name, "size": size, "human": human_size(size),
                                "incoming": true, "needs_accept": true }));
                        } else {
                            let _ = app.emit("file", json!({ "event": "error", "id": hex::encode(id),
                                "detail": "too many simultaneous file transfers" }));
                        }
                    }
                    Frame::FileChunk { id, data } => {
                        if gate.accepts_chunk(&id) {
                            if let Some(inc) = sinks.get_mut(&id) {
                                let before = inc.received;
                                match inc.write_chunk(&data) {
                                    Ok(()) => {
                                        const MIB: u64 = 1 << 20;
                                        if inc.received == inc.size || before / MIB != inc.received / MIB {
                                            let _ = app.emit("file", json!({ "event": "progress", "id": hex::encode(id),
                                                "received": inc.received, "size": inc.size }));
                                        }
                                    }
                                    Err(e) => {
                                        sinks.remove(&id);
                                        gate.finish(&id);
                                        let _ = app.emit("file", json!({ "event": "error", "id": hex::encode(id), "detail": e.to_string() }));
                                    }
                                }
                            }
                        }
                    }
                    Frame::FileEnd { id } => {
                        gate.finish(&id);
                        if let Some(inc) = sinks.remove(&id) {
                            let name = inc.name.clone();
                            match inc.finish() {
                                Ok(path) => {
                                    let _ = app.emit("file", json!({ "event": "saved", "id": hex::encode(id),
                                        "name": name, "path": path.display().to_string() }));
                                    persist_msg(&app, &peer_label, &format!("📎 {name} (saved to Downloads)"), true).await;
                                }
                                Err(e) => {
                                    let _ = app.emit("file", json!({ "event": "error", "id": hex::encode(id), "detail": e.to_string() }));
                                }
                            }
                        }
                    }
                    Frame::FileAccept { id } => {
                        let _ = app.emit("file", json!({ "event": "peer-accepted", "id": hex::encode(id) }));
                    }
                    Frame::FileReject { id } => {
                        let _ = app.emit("file", json!({ "event": "peer-rejected", "id": hex::encode(id) }));
                    }
                    Frame::Group(_) => {}
                }
            }
        }
    }

    *app.state::<ChatState>().file_decisions.lock().await = None;
    {
        *app.state::<ChatState>().sender.lock().await = None;
    }
    let _ = app.emit("status", json!({ "state": "disconnected" }));
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(ChatState::default())
        .setup(|app| {
            // Open the plaintext transcript up front (no passphrase) so history is
            // ready before the first message. Best-effort: a failure just means no
            // saved history this run.
            let handle = app.handle().clone();
            tauri::async_runtime::block_on(async move {
                if let Ok(h) = History::open() {
                    *handle.state::<ChatState>().history.lock().await = Some(h);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            version,
            can_self_update,
            open_url,
            get_prefs,
            save_hub_prefs,
            clear_hub_prefs,
            list_conversations,
            load_conversation,
            host,
            connect,
            connect_hub,
            hub_send,
            hub_open_dm,
            hub_create_room,
            send_message,
            host_group,
            join_group,
            disconnect,
            clear_history,
            file_begin,
            file_chunk,
            file_end,
            file_accept,
            file_reject
        ])
        .run(tauri::generate_context!())
        .expect("error while running FamChat");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression tripwire for the Content-Security-Policy: fails the build if a
    /// future edit removes it or weakens the parts that matter.
    #[test]
    fn csp_is_present_and_strict() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json must parse");
        let csp = conf["app"]["security"]["csp"]
            .as_str()
            .expect("a Content-Security-Policy must be set (app.security.csp is null or missing)");
        for needle in [
            "default-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
        ] {
            assert!(
                csp.contains(needle),
                "CSP is missing `{needle}`; CSP was: {csp}"
            );
        }
        let script_src = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src"))
            .expect("CSP must set script-src");
        assert_eq!(
            script_src, "script-src 'self'",
            "script-src must be exactly 'self' (no inline, eval, or remote script)"
        );
        assert!(
            !csp.contains("unsafe-eval"),
            "CSP must never allow unsafe-eval"
        );
    }

    /// Leaving a chat must null the live session: abort+drain the background tasks,
    /// drop the send handles, and forget the active conversation.
    #[tokio::test]
    async fn teardown_clears_live_session_state() {
        let st = ChatState::default();
        let handle = tauri::async_runtime::spawn(async { std::future::pending::<()>().await });
        st.tasks.lock().await.push(handle);
        *st.active.lock().await = Some(Active {
            id: "room".into(),
            title: "Room".into(),
        });
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<([u8; 16], bool)>();
        *st.file_decisions.lock().await = Some(tx);

        st.clear().await;
        assert!(
            st.tasks.lock().await.is_empty(),
            "background tasks must be aborted and drained"
        );
        assert!(
            st.active.lock().await.is_none(),
            "the active conversation must be forgotten"
        );
        assert!(
            st.file_decisions.lock().await.is_none(),
            "the file-decision channel must be dropped"
        );
        assert!(st.sender.lock().await.is_none());
        assert!(st.group.lock().await.is_none());
    }
}
