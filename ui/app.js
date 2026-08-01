(() => {
  // preview hook: `#connect` shows the overlay in a plain browser for design review
  if (location.hash.includes('connect')) {
    var ovp = document.getElementById('connect-overlay');
    if (ovp) ovp.style.display = 'flex';
  }
  const T = window.__TAURI__;
  if (!T) return; // plain browser: keep the static design preview
  const invoke = T.core.invoke, listen = T.event.listen;
  const notif = T.notification; // native OS notifications plugin
  const esc = (s) => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

  // Apply the saved theme before rendering (default light; dark is opt-in via
  // Settings and remembered here). localStorage is same-origin only.
  try { if (localStorage.getItem('famchat-theme') === 'dark') document.documentElement.setAttribute('data-theme', 'dark'); } catch (e) {}

  // Live surface: no conversation open yet, so the chat shows its empty state.
  const msgs = document.getElementById('messages');
  msgs.innerHTML = '';
  const chatEl = document.querySelector('.chat');
  const peerName = document.querySelector('.peer-name');
  const peerFp = document.querySelector('.peer-fp');
  const headTile = document.querySelector('.chat-peer > .tile');
  if (peerName) peerName.childNodes[0].nodeValue = 'Chat ';
  let currentPeerName = 'Chat';   // the room/peer name, for message labels
  let lastMsgSender = null;       // groups consecutive lines under one header
  if (chatEl) chatEl.classList.add('empty');
  const overlay = document.getElementById('connect-overlay');
  const ovMsg = document.getElementById('ov-msg');
  const convoList = document.getElementById('convoList');
  let sidebarSums = [];
  let activeName = '';
  let hosting = false;
  let hubActive = false;   // true while connected to a family hub (persistent room)

  // A stable per-device id so a hub can hold messages addressed to this device.
  function deviceId() {
    let id = null;
    try { id = localStorage.getItem('famchat-device-id'); } catch (e) {}
    if (!id) {
      id = (window.crypto && crypto.randomUUID) ? crypto.randomUUID()
        : 'dev-' + Math.random().toString(36).slice(2) + Date.now().toString(36);
      try { localStorage.setItem('famchat-device-id', id); } catch (e) {}
    }
    return id;
  }   // true when we started (host) this chat, so we keep the invite address handy

  const leaveBtn = document.getElementById('leaveBtn');
  const attachBtn = document.querySelector('.composer .attach');
  const fileInput = document.getElementById('fileInput');
  const fileBubbles = {}; // transfer id -> incoming bubble element
  // Demo mode: a purely local sandbox for trying the UI with no one else online.
  let demoMode = false;

  // ---- Native notifications ---------------------------------------------------
  // Prefer the plugin's JS global (window.__TAURI__.notification); fall back to the
  // raw plugin commands, which are always registered regardless of JS bindings.
  let notifyAllowed = false;
  async function notifPermGranted() {
    if (notif && notif.isPermissionGranted) { try { return await notif.isPermissionGranted(); } catch (e) {} }
    try { return await invoke('plugin:notification|is_permission_granted'); } catch (e) { return false; }
  }
  async function notifRequestPerm() {
    if (notif && notif.requestPermission) { try { return (await notif.requestPermission()) === 'granted'; } catch (e) {} }
    try { return (await invoke('plugin:notification|request_permission')) === 'granted'; } catch (e) { return false; }
  }
  async function ensureNotifyPermission() {
    try {
      let granted = await notifPermGranted();
      if (!granted) granted = await notifRequestPerm();
      notifyAllowed = !!granted;
    } catch (e) { notifyAllowed = false; }
  }
  function notify(title, body) {
    if (!notifyAllowed) return;
    if (notif && notif.sendNotification) { try { notif.sendNotification({ title: title || 'FamChat', body: body || '' }); return; } catch (e) {} }
    try { invoke('plugin:notification|notify', { options: { title: title || 'FamChat', body: body || '' } }); } catch (e) {}
  }

  // ---- In-app confirm dialog (guards Leave / delete against misclicks) ---------
  const confirmOverlay = document.getElementById('confirm-overlay');
  const cfTitle = document.getElementById('cf-title');
  const cfMsg = document.getElementById('cf-msg');
  const cfOk = document.getElementById('cf-ok');
  const cfCancel = document.getElementById('cf-cancel');
  let cfResolve = null;
  function askConfirm(opts) {
    return new Promise((resolve) => {
      cfResolve = resolve;
      cfTitle.textContent = opts.title || 'Are you sure?';
      cfMsg.textContent = opts.message || '';
      cfOk.textContent = opts.confirmLabel || 'Confirm';
      cfOk.classList.toggle('danger', !!opts.danger);
      confirmOverlay.style.display = 'flex';
      cfOk.focus();
    });
  }
  function closeConfirm(result) {
    if (confirmOverlay.style.display !== 'flex' && cfResolve === null) return;
    confirmOverlay.style.display = 'none';
    const r = cfResolve; cfResolve = null;
    if (r) r(result);
  }
  if (cfOk) cfOk.addEventListener('click', () => closeConfirm(true));
  if (cfCancel) cfCancel.addEventListener('click', () => closeConfirm(false));
  if (confirmOverlay) confirmOverlay.addEventListener('click', (e) => { if (e.target === confirmOverlay) closeConfirm(false); });
  document.addEventListener('keydown', (e) => {
    if (!confirmOverlay || confirmOverlay.style.display !== 'flex') return;
    if (e.key === 'Escape') { e.preventDefault(); closeConfirm(false); }
    else if (e.key === 'Enter') { e.preventDefault(); closeConfirm(true); }
  });

  function forgetHub() {
    hubActive = false;
    try {
      localStorage.removeItem('famchat-hub-address');
      localStorage.removeItem('famchat-hub-word');
      localStorage.removeItem('famchat-hub-name');
    } catch (e) {}
  }
  if (leaveBtn) leaveBtn.addEventListener('click', async () => {
    const ok = await askConfirm({
      title: hubActive ? 'Disconnect from the hub?' : 'Leave this chat?',
      message: demoMode ? 'This exits the demo.'
        : hubActive ? 'Stops using the family hub on this device. Your saved messages stay, and you can reconnect with the hub address anytime.'
        : 'Ends the current chat. Your saved messages stay — you can reopen it anytime.',
      confirmLabel: hubActive ? 'Disconnect' : 'Leave',
    });
    if (!ok) return;
    if (demoMode) { exitDemo(); return; }
    if (hubActive) forgetHub();
    try { await invoke('disconnect'); } catch (e) {}
  });

  // ---- Demo mode --------------------------------------------------------------
  const sealNote = document.querySelector('.seal-note');
  const demoReplies = [
    "Nice — that showed up right away.",
    "This is just a demo, so nothing actually left this window.",
    "Try the paperclip to see how sending a photo or file looks.",
    "When you start a real chat, everyone on your Wi-Fi can join with the family word.",
    "Hit Leave up top whenever you want to come back here.",
  ];
  let demoReplyIdx = 0;
  function enterDemo() {
    demoMode = true;
    if (overlay) overlay.style.display = 'none';
    startThread('Demo', 'Demo');
    if (leaveBtn) leaveBtn.style.display = 'flex';
    if (attachBtn) attachBtn.style.display = 'flex';
    setFp('<span class="fpdot demo"></span> demo — not a real chat');
    addMsg('Welcome to the FamChat demo — a local sandbox with no one else connected.', true);
    addMsg("Type below and I'll reply. Nothing here is sent anywhere.", true);
    demoReplyIdx = 0;
    if (input) input.focus();
  }
  function exitDemo() {
    demoMode = false;
    if (leaveBtn) leaveBtn.style.display = 'none';
    if (peerName) peerName.childNodes[0].nodeValue = 'Chat ';
    setFp('');
    msgs.innerHTML = '';
    showEmpty();
    if (overlay) overlay.style.display = 'none';
  }
  const demoBtn = document.getElementById('ov-demo');
  if (demoBtn) demoBtn.addEventListener('click', enterDemo);

  function setFp(html) { if (peerFp) peerFp.innerHTML = html; }

  // ---- Message rendering: flat rows -------------------------------------------
  const AV_COLORS = ['#5678a0', '#3f9a8c', '#9160a0', '#b8724f', '#c1913f', '#4f6c90'];
  function avatarColor(name) { let h = 0; const s = name || ''; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return AV_COLORS[h % AV_COLORS.length]; }
  function initialOf(name) { return ((name || '?').trim().charAt(0) || '?').toUpperCase(); }
  function nowTime() { const d = new Date(); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); }
  function scrollDown() { msgs.scrollTop = msgs.scrollHeight; }

  function appendLine(name, me, node) {
    const key = (me ? 'me:' : 'them:') + name;
    const last = msgs.lastElementChild;
    let content;
    if (lastMsgSender === key && last && last.classList.contains('msg')) {
      content = last.querySelector('.msg-content');
    } else {
      const row = document.createElement('div');
      row.className = 'msg first ' + (me ? 'me' : 'them');
      row.innerHTML = '<div class="msg-avatar"><div class="tile" style="background:' +
        (me ? '#22a06b' : avatarColor(name)) + '">' + esc(initialOf(name)) + '</div></div>' +
        '<div class="msg-content"><div class="msg-head"><span class="msg-name">' + esc(name) +
        '</span><span class="msg-time">' + nowTime() + '</span></div></div>';
      msgs.appendChild(row);
      content = row.querySelector('.msg-content');
      lastMsgSender = key;
    }
    content.appendChild(node);
    scrollDown();
  }
  function addMsg(text, incoming) {
    const line = document.createElement('div');
    line.className = 'msg-line settle';
    line.textContent = text;
    appendLine(incoming ? currentPeerName : 'You', !incoming, line);
    return line;
  }

  function showChat() { if (chatEl) chatEl.classList.remove('empty'); }
  function showEmpty() { if (chatEl) chatEl.classList.add('empty'); lastMsgSender = null; hideInviteBanner(); }
  function startThread(label, dividerText) {
    currentPeerName = label || 'Chat';
    showChat();
    hideInviteBanner();
    lastMsgSender = null;
    msgs.innerHTML = '<div class="day"><span>' + esc(dividerText || 'Today') + '</span></div>';
    if (peerName) peerName.childNodes[0].nodeValue = currentPeerName + ' ';
    if (headTile) { headTile.style.background = avatarColor(currentPeerName); if (headTile.firstChild) headTile.firstChild.nodeValue = initialOf(currentPeerName); }
  }

  function renderSidebar(sums) {
    sidebarSums = sums || [];
    if (!sidebarSums.length) {
      convoList.innerHTML = '<div class="list-label label">Chats</div>' +
        '<div style="padding:12px 12px 6px;color:var(--ink-3);font-size:12.5px;line-height:1.55">No chats yet.<br>Hit “+” to start one on your home network.</div>';
      return;
    }
    convoList.innerHTML = '<div class="list-label label">Chats</div>' +
      sidebarSums.map((c) => {
        const count = c.count ? '<div class="convo-count">' + (c.count > 99 ? '99+' : c.count) + '</div>' : '';
        return '<div class="convo" data-id="' + esc(c.id) + '" data-title="' + esc(c.title) + '">' +
          '<div class="tile" style="background:' + avatarColor(c.title) + '">' + esc(initialOf(c.title)) + '</div>' +
          '<div class="convo-body"><div class="convo-top">' +
          '<div class="convo-name">' + esc(c.title) + '</div>' + count + '</div>' +
          '<div class="convo-bottom"><div class="convo-preview">' + esc(c.last || '') + '</div></div>' +
          '</div></div>';
      }).join('');
    convoList.querySelectorAll('.convo').forEach((el) =>
      el.addEventListener('click', () => openSaved(el.getAttribute('data-id'), el.getAttribute('data-title'))));
  }

  async function openSaved(id, title) {
    try {
      const list = await invoke('load_conversation', { id });
      startThread(title || 'Chat', 'Saved messages');
      setFp('<span class="fpdot"></span> saved on this device');
      if (leaveBtn) leaveBtn.style.display = 'none'; // not live, just viewing history
      for (const m of list) addMsg(m.text, m.incoming);
      convoList.querySelectorAll('.convo').forEach((el) => el.classList.toggle('active', el.getAttribute('data-id') === id));
    } catch (err) { if (ovMsg) ovMsg.textContent = 'Could not open: ' + err; }
  }

  function ensureSidebar(id, title) {
    if (!id || sidebarSums.some((s) => s.id === id)) return;
    renderSidebar([{ id, title: title || id, last: '', count: 0, last_ts: 0 }].concat(sidebarSums));
  }

  // Render PEER messages from the event (our own are rendered locally by doSend),
  // and pop a native notification when a message lands while the window is unfocused.
  listen('message', (e) => {
    const p = e.payload;
    if (!p.incoming) return;
    addMsg(p.text, true);
    if (!document.hasFocus()) notify(p.from || currentPeerName || 'FamChat', p.text);
  });

  // ---- Host "share this address" panel ----------------------------------------
  const ovForm = document.getElementById('ov-form');
  const ovInvite = document.getElementById('ov-invite');
  const invStatus = document.getElementById('inv-status');
  const invAddrWrap = document.getElementById('inv-addr-wrap');
  const invAddr = document.getElementById('inv-addr');
  const invCopy = document.getElementById('inv-copy');
  const invHint = document.getElementById('inv-hint');
  const invCancel = document.getElementById('inv-cancel');
  let inviteAddress = '';
  const spin = '<span class="spin"></span>';

  function showConnectForm() {
    if (ovForm) ovForm.style.display = 'block';
    if (ovInvite) ovInvite.style.display = 'none';
    if (invAddrWrap) invAddrWrap.style.display = 'none';
    if (invAddr) invAddr.textContent = '';
    inviteAddress = '';
  }
  function showInvitePanel(mode) {
    if (ovForm) ovForm.style.display = 'none';
    if (ovInvite) ovInvite.style.display = 'block';
    if (invAddrWrap) invAddrWrap.style.display = 'none';
    if (invHint) invHint.textContent = '';
    if (invStatus) invStatus.innerHTML = spin + (mode === 'join' ? 'Connecting…' : 'Setting up your chat…');
  }
  function showHostAddress(addr) {
    if (!addr) return;
    inviteAddress = addr;
    if (ovInvite) ovInvite.style.display = 'block';
    if (ovForm) ovForm.style.display = 'none';
    if (invStatus) invStatus.textContent = 'Ready — share this address with your family';
    if (invAddr) invAddr.textContent = addr;
    if (invAddrWrap) invAddrWrap.style.display = 'block';
    if (invHint) invHint.textContent = 'They open FamChat → Join a chat → paste this address and type the same family word. Keep this window open until they join.';
    setFp('<span class="fpdot"></span> waiting for them to join…');
  }
  if (invCancel) invCancel.addEventListener('click', async () => {
    try { await invoke('disconnect'); } catch (e) {}
    showConnectForm();
  });
  if (invCopy) invCopy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(inviteAddress);
      invCopy.textContent = 'Copied!';
      setTimeout(() => { invCopy.textContent = 'Copy address'; }, 1500);
    } catch (e) {
      try {
        const r = document.createRange(); r.selectNodeContents(invAddr);
        const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
        invCopy.textContent = 'Selected — press Ctrl+C';
      } catch (_) {}
    }
  });

  // Invite banner shown inside the chat while you host a room, so the address to
  // share stays reachable (a group host is dropped straight into the room).
  const inviteBanner = document.getElementById('invite-banner');
  const ibAddr = document.getElementById('ib-addr');
  function showInviteBanner(addr) { if (!inviteBanner || !addr) return; ibAddr.textContent = addr; inviteBanner.style.display = 'flex'; }
  function hideInviteBanner() { if (inviteBanner) inviteBanner.style.display = 'none'; }
  const ibCopy = document.getElementById('ib-copy');
  if (ibCopy) ibCopy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(ibAddr.textContent); ibCopy.textContent = 'Copied!'; setTimeout(() => { ibCopy.textContent = 'Copy'; }, 1500); }
    catch (e) { try { const r = document.createRange(); r.selectNodeContents(ibAddr); const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r); } catch (_) {} }
  });
  const ibClose = document.getElementById('ib-close');
  if (ibClose) ibClose.addEventListener('click', hideInviteBanner);

  listen('status', (e) => {
    const s = e.payload;
    if (s.state === 'listening') {
      inviteAddress = s.address;
      // A 2-person host waits here showing the address until someone joins. A group
      // host is joined into the room immediately (connected fires next), so skip the
      // modal and hand them the address via the in-chat banner instead.
      if (!s.group) showHostAddress(s.address);
    }
    else if (s.state === 'connecting') {
      if (invStatus) invStatus.innerHTML = spin + (s.transport === 'hub' ? 'Connecting to your family hub…' : 'Connecting… you’re in as soon as the family word matches.');
      setFp('<span class="fpdot"></span> ' + (s.reconnecting ? 'reconnecting…' : 'connecting…'));
    }
    else if (s.state === 'connected') {
      hubActive = s.transport === 'hub';
      if (overlay) overlay.style.display = 'none';
      showConnectForm();
      startThread(s.conversation_title || activeName || 'Chat');
      if (leaveBtn) leaveBtn.style.display = 'flex';
      if (attachBtn) attachBtn.style.display = (s.transport === 'group' || s.transport === 'hub') ? 'none' : 'flex';
      if (s.conversation_id) ensureSidebar(s.conversation_id, s.conversation_title);
      setFp('<span class="fpdot"></span> ' + (s.transport === 'hub' ? 'connected to your family hub' : 'on your home network'));
      // Host of a group room: keep the address visible so you can still invite people.
      if (hosting && s.transport === 'group' && inviteAddress) showInviteBanner(inviteAddress);
    }
    else if (s.state === 'error') { if (ovInvite && ovInvite.style.display !== 'none' && invStatus) { invStatus.textContent = 'Couldn’t connect: ' + s.detail; } if (ovMsg) ovMsg.textContent = 'Error: ' + s.detail; }
    else if (s.state === 'disconnected') { if (leaveBtn) leaveBtn.style.display = 'none'; showEmpty(); refreshSidebar(); }
  });

  async function refreshSidebar() {
    try { renderSidebar(await invoke('list_conversations')); } catch (e) {}
  }

  // ---- Composer ---------------------------------------------------------------
  const input = document.querySelector('.composer .field-input');
  const sendBtn = document.querySelector('.composer .send');
  const warnSmall = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>';
  function markSendFailed(line, text, err) {
    if (!line || !line.parentNode) return;
    line.classList.remove('sending');
    line.classList.add('failed');
    let note = line.nextElementSibling;
    if (!(note && note.classList && note.classList.contains('send-fail'))) {
      note = document.createElement('div');
      note.className = 'send-fail';
      note.innerHTML = warnSmall + '<span>Not delivered</span> · <button class="retry" type="button">Retry</button>';
      line.parentNode.insertBefore(note, line.nextSibling);
      note.querySelector('.retry').addEventListener('click', async () => {
        note.remove();
        line.classList.remove('failed');
        line.classList.add('sending');
        try { await invoke('send_message', { text }); line.classList.remove('sending'); }
        catch (e) { markSendFailed(line, text, e); }
      });
    }
    note.title = '' + (err || '');
  }

  async function doSend() {
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    if (demoMode) {
      addMsg(text, false);
      const reply = demoReplies[demoReplyIdx % demoReplies.length];
      demoReplyIdx++;
      setTimeout(() => { if (demoMode) addMsg(reply, true); }, 700);
      return;
    }
    const line = addMsg(text, false);
    line.classList.add('sending');
    try {
      await invoke('send_message', { text });
      line.classList.remove('sending');
    } catch (err) {
      markSendFailed(line, text, err);
    }
  }
  if (sendBtn) sendBtn.addEventListener('click', doSend);
  if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doSend(); } });

  // ---- File transfer (2-party) ------------------------------------------------
  const FILE_CHUNK = 32 * 1024; // must match famchat_core CHUNK_SIZE
  const fileIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>';
  function humanSize(b) {
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let v = b, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return i === 0 ? b + ' B' : v.toFixed(1) + ' ' + u[i];
  }
  function hex(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0'); return s; }
  function addFileBubble(incoming, name, sizeText) {
    const card = document.createElement('div');
    card.className = 'filecard';
    card.innerHTML = '<div class="file-ic">' + fileIcon + '</div>' +
      '<div class="file-meta"><div class="fname"></div><div class="fsize"></div></div>';
    card.querySelector('.fname').textContent = name;
    card.querySelector('.fsize').textContent = sizeText;
    appendLine(incoming ? currentPeerName : 'You', !incoming, card);
    return card;
  }
  const setFileSub = (el, text) => { const fs = el && el.querySelector('.fsize'); if (fs) fs.textContent = text; };
  function setFileError(el, detail) {
    const fs = el && el.querySelector('.fsize');
    if (fs) { fs.textContent = 'Failed'; fs.title = detail || ''; }
    if (el) el.classList.add('file-failed');
  }
  async function sendFile(file) {
    const bubble = addFileBubble(false, file.name, humanSize(file.size));
    if (demoMode) {
      let sent = 0; const total = file.size || 1;
      const step = Math.max(1, Math.floor(total / 8));
      const iv = setInterval(() => {
        sent = Math.min(total, sent + step);
        setFileSub(bubble, Math.floor(sent * 100 / total) + '% · ' + humanSize(file.size));
        if (sent >= total || !demoMode) { clearInterval(iv); setFileSub(bubble, 'Sent · demo · ' + humanSize(file.size)); }
      }, 180);
      return;
    }
    let id;
    try { id = await invoke('file_begin', { name: file.name, size: file.size }); }
    catch (err) { setFileError(bubble, '' + err); return; }
    setFileSub(bubble, 'Waiting for them to accept…');
    const decision = await waitForPeerDecision(id);
    if (decision !== true) {
      setFileError(bubble, decision === false ? 'Declined' : 'No response');
      return;
    }
    try {
      let sent = 0;
      for (let off = 0; off < file.size; off += FILE_CHUNK) {
        const slice = file.slice(off, Math.min(off + FILE_CHUNK, file.size));
        const buf = new Uint8Array(await slice.arrayBuffer());
        const h = hex(buf);
        await invoke('file_chunk', { id, dataHex: h, data_hex: h });
        sent += buf.length;
        setFileSub(bubble, (file.size ? Math.floor(sent * 100 / file.size) : 100) + '% · ' + humanSize(file.size));
      }
      await invoke('file_end', { id });
      setFileSub(bubble, 'Sent · ' + humanSize(file.size));
    } catch (err) { setFileError(bubble, '' + err); }
  }
  const outgoingWaiters = {};
  function waitForPeerDecision(id) {
    return new Promise((resolve) => {
      outgoingWaiters[id] = resolve;
      setTimeout(() => { if (outgoingWaiters[id]) { delete outgoingWaiters[id]; resolve(null); } }, 120000);
    });
  }
  if (attachBtn && fileInput) {
    attachBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files && fileInput.files[0];
      fileInput.value = '';
      if (file) await sendFile(file);
    });
  }
  listen('file', async (e) => {
    const f = e.payload;
    if (f.event === 'offer') {
      if (!f.incoming) return;
      const ok = await askConfirm({
        title: 'Accept this file?',
        message: (f.name || 'file') + '  ·  ' + (f.human || '') +
          '\n\nSomeone wants to send you this. Nothing is saved to your device unless you accept.',
        confirmLabel: 'Accept & save',
      });
      if (ok) {
        fileBubbles[f.id] = addFileBubble(true, f.name, 'Receiving · ' + f.human);
        try { await invoke('file_accept', { id: f.id }); } catch (err) {}
      } else {
        try { await invoke('file_reject', { id: f.id }); } catch (err) {}
      }
    } else if (f.event === 'peer-accepted') {
      const w = outgoingWaiters[f.id]; if (w) { delete outgoingWaiters[f.id]; w(true); }
    } else if (f.event === 'peer-rejected') {
      const w = outgoingWaiters[f.id]; if (w) { delete outgoingWaiters[f.id]; w(false); }
    } else if (f.event === 'progress') {
      const el = fileBubbles[f.id];
      if (el) setFileSub(el, (f.size ? Math.floor(f.received * 100 / f.size) : 0) + '% · ' + humanSize(f.size));
    } else if (f.event === 'saved') {
      const el = fileBubbles[f.id];
      if (el) { setFileSub(el, 'Saved to Downloads'); if (el.querySelector('.fname')) el.querySelector('.fname').title = f.path || ''; }
      if (!document.hasFocus()) notify(currentPeerName || 'FamChat', 'Sent you a file: ' + (el && el.querySelector('.fname') ? el.querySelector('.fname').textContent : 'file'));
      delete fileBubbles[f.id];
    } else if (f.event === 'error') {
      const el = fileBubbles[f.id];
      if (el) setFileError(el, f.detail);
      delete fileBubbles[f.id];
    }
  });

  // ---- Start / Join / Family hub ----------------------------------------------
  let ovMode = 'start';
  const ovGo = document.getElementById('ov-go');
  const ovAddrWrap = document.getElementById('ov-addr-wrap');
  const ovAddrLabel = document.getElementById('ov-addr-label');
  const ovAddrHint = document.getElementById('ov-addr-hint');
  const ovNameLabel = document.getElementById('ov-name-label');
  const ovNameInput = document.getElementById('ov-name');
  const ovOpts = document.querySelector('.ov-opts');
  const segStart = document.getElementById('seg-start');
  const segJoin = document.getElementById('seg-join');
  const segHub = document.getElementById('seg-hub');
  const ovExplain = document.getElementById('ov-explain');
  const ovGroupCb = document.getElementById('ov-group');
  function explainText(m) {
    const isGroup = ovGroupCb && ovGroupCb.checked;
    if (m === 'hub') {
      return '<span class="step"><span class="n">1</span>Enter your family hub’s address — the always-on laptop.</span>' +
             '<span class="step"><span class="n">2</span>Type your family word and your name.</span>' +
             '<span class="step"><span class="n">3</span>Connect. You stay signed in, and get messages even ones sent while you were away.</span>';
    }
    if (m === 'join') {
      return '<span class="step"><span class="n">1</span>Paste the address the host shared with you above.</span>' +
             '<span class="step"><span class="n">2</span>Type the family word everyone agreed on.</span>' +
             '<span class="step"><span class="n">3</span>Hit Join — you connect once the word matches.</span>';
    }
    return '<span class="step"><span class="n">1</span>Hit Start — FamChat gives you an address to share with ' + (isGroup ? 'the family' : 'them') + '.</span>' +
           '<span class="step"><span class="n">2</span>Pick a family word you all use to get in.</span>' +
           '<span class="step"><span class="n">3</span>' + (isGroup ? 'Everyone joins' : 'They join') + ' with that address and the same word. Keep this window open while you wait.</span>';
  }
  function setMode(m) {
    ovMode = m;
    segStart.classList.toggle('on', m === 'start');
    segJoin.classList.toggle('on', m === 'join');
    if (segHub) segHub.classList.toggle('on', m === 'hub');
    ovAddrWrap.style.display = (m === 'join' || m === 'hub') ? 'block' : 'none';
    if (ovOpts) ovOpts.style.display = m === 'hub' ? 'none' : 'flex';
    if (ovAddrLabel) ovAddrLabel.textContent = m === 'hub' ? 'Hub address' : 'Their address';
    if (ovAddrHint) ovAddrHint.textContent = m === 'hub'
      ? 'The address of your always-on hub laptop, e.g. 192.168.1.50'
      : 'The address the host shared with you. However they sent it (text, a note) is fine.';
    if (ovNameLabel) ovNameLabel.textContent = m === 'hub' ? 'Your name' : 'Chat name';
    if (ovNameInput) ovNameInput.placeholder = m === 'hub' ? 'e.g. Mom — what your family sees' : 'e.g. Mom, or Family Room';
    ovGo.textContent = m === 'join' ? 'Join' : (m === 'hub' ? 'Connect' : 'Start');
    if (ovExplain) ovExplain.innerHTML = explainText(m);
    if (ovMsg) ovMsg.textContent = '';
  }
  if (ovGroupCb) ovGroupCb.addEventListener('change', () => { if (ovExplain) ovExplain.innerHTML = explainText(ovMode); });
  if (segStart) segStart.addEventListener('click', () => setMode('start'));
  if (segJoin) segJoin.addEventListener('click', () => setMode('join'));
  if (segHub) segHub.addEventListener('click', () => setMode('hub'));

  if (ovGo) ovGo.addEventListener('click', async () => {
    if (demoMode) { demoMode = false; if (peerName) peerName.childNodes[0].nodeValue = 'Chat '; }
    const code = document.getElementById('ov-code').value.trim();
    if (!code) { ovMsg.textContent = 'Enter your family word first.'; return; }
    // Family hub: connect to the always-on room and remember it for next launch.
    if (ovMode === 'hub') {
      const addr = document.getElementById('ov-addr').value.trim();
      if (!addr) { ovMsg.textContent = 'Enter the hub address.'; return; }
      const yourName = (ovNameInput && ovNameInput.value || '').trim();
      const id = deviceId();
      try {
        localStorage.setItem('famchat-hub-address', addr);
        localStorage.setItem('famchat-hub-word', code);
        localStorage.setItem('famchat-hub-name', yourName);
      } catch (e) {}
      hubActive = true;
      activeName = 'Family';
      showInvitePanel('join');
      if (invStatus) invStatus.innerHTML = spin + 'Connecting to your family hub…';
      try { await invoke('connect_hub', { address: addr, code, name: yourName, id }); }
      catch (err) { if (invStatus) invStatus.textContent = 'Error: ' + err; }
      return;
    }
    const group = !!(ovGroupCb && ovGroupCb.checked);
    const name = (document.getElementById('ov-name').value || '').trim();
    activeName = name;
    hosting = ovMode === 'start';
    let joinAddress = '';
    if (ovMode === 'join') {
      joinAddress = document.getElementById('ov-addr').value.trim();
      if (!joinAddress) { ovMsg.textContent = 'Paste the address they shared.'; return; }
    }
    showInvitePanel(ovMode);
    try {
      if (ovMode === 'join') {
        await invoke(group ? 'join_group' : 'connect', { address: joinAddress, code, name });
      } else {
        const addr = await invoke(group ? 'host_group' : 'host', { bind: '', code, name });
        if (addr && invAddr && !invAddr.textContent) showHostAddress(addr);
      }
    } catch (err) { if (invStatus) invStatus.textContent = 'Error: ' + err; }
  });

  // Open / close the Start-a-chat modal. Never a trap: "+", empty-state button
  // open it; X / backdrop / Esc close it (disconnecting a half-open host).
  function openConnect() { showConnectForm(); setMode('start'); overlay.style.display = 'flex'; const c = document.getElementById('ov-code'); if (c) c.focus(); }
  function closeConnect() { overlay.style.display = 'none'; }
  function cancelConnect() {
    const inviting = ovInvite && ovInvite.style.display !== 'none';
    if (inviting && !demoMode) { invoke('disconnect').catch(() => {}); }
    closeConnect();
    showConnectForm();
  }
  const newBtn = document.querySelector('.side-head .icon-btn');
  if (newBtn) newBtn.addEventListener('click', openConnect);
  const emptyStart = document.getElementById('empty-start');
  if (emptyStart) emptyStart.addEventListener('click', openConnect);
  const ovClose = document.getElementById('ov-close');
  if (ovClose) ovClose.addEventListener('click', cancelConnect);
  if (overlay) overlay.addEventListener('click', (e) => { if (e.target === overlay) cancelConnect(); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (confirmOverlay && confirmOverlay.style.display === 'flex') return;
    if (overlay && overlay.style.display === 'flex') { e.preventDefault(); cancelConnect(); }
  });

  // ---- Settings (theme + clear all chats) -------------------------------------
  const settingsOverlay = document.getElementById('settings-overlay');
  const settingsBtn = document.getElementById('settingsBtn');
  const setLight = document.getElementById('set-light');
  const setDark = document.getElementById('set-dark');
  const setVer = document.getElementById('set-ver');
  function currentTheme() { return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light'; }
  function applyTheme(t) {
    if (t === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
    try { localStorage.setItem('famchat-theme', t); } catch (e) {}
    if (setLight) setLight.classList.toggle('on', t !== 'dark');
    if (setDark) setDark.classList.toggle('on', t === 'dark');
  }
  function openSettings() {
    applyTheme(currentTheme());
    if (setVer && !setVer.textContent) invoke('version').then((v) => { setVer.textContent = 'FamChat v' + v; }).catch(() => {});
    if (settingsOverlay) settingsOverlay.style.display = 'flex';
  }
  function closeSettings() { if (settingsOverlay) settingsOverlay.style.display = 'none'; }
  if (settingsBtn) settingsBtn.addEventListener('click', openSettings);
  const setClose = document.getElementById('set-close');
  if (setClose) setClose.addEventListener('click', closeSettings);
  if (settingsOverlay) settingsOverlay.addEventListener('click', (e) => { if (e.target === settingsOverlay) closeSettings(); });
  if (setLight) setLight.addEventListener('click', () => applyTheme('light'));
  if (setDark) setDark.addEventListener('click', () => applyTheme('dark'));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && settingsOverlay && settingsOverlay.style.display === 'flex' &&
        (!confirmOverlay || confirmOverlay.style.display !== 'flex')) { e.preventDefault(); closeSettings(); }
  });
  const wipeAllBtn = document.getElementById('set-wipe');
  if (wipeAllBtn) wipeAllBtn.addEventListener('click', async () => {
    const ok = await askConfirm({
      title: 'Delete all saved chats?',
      message: 'This permanently deletes every saved chat on this device, and ends any live chat. It cannot be undone.',
      confirmLabel: 'Delete everything',
      danger: true,
    });
    if (!ok) return;
    try { await invoke('clear_history'); }
    catch (e) { await askConfirm({ title: 'Delete failed', message: '' + e, confirmLabel: 'OK' }); return; }
    sidebarSums = [];
    renderSidebar([]);
    if (peerName) peerName.childNodes[0].nodeValue = 'Chat ';
    setFp('');
    showEmpty();
    closeSettings();
  });

  // ---- Updates (signed auto-update from GitHub Releases) ----------------------
  const updBtn = document.getElementById('set-check-upd');
  const updDesc = document.getElementById('set-upd-desc');
  const autoUpd = document.getElementById('set-autoupd');
  if (autoUpd) {
    autoUpd.checked = localStorage.getItem('famchat-autoupdate') !== 'off';
    autoUpd.addEventListener('change', () => { try { localStorage.setItem('famchat-autoupdate', autoUpd.checked ? 'on' : 'off'); } catch (e) {} });
  }
  function setUpdDesc(t) { if (updDesc) updDesc.textContent = t; }
  async function checkForUpdate(manual) {
    if (!T.updater || !T.updater.check) { if (manual) await askConfirm({ title: 'Updates unavailable', message: 'This build can’t check for updates.', confirmLabel: 'OK' }); return; }
    if (manual) setUpdDesc('Checking…');
    let update;
    try { update = await T.updater.check(); }
    catch (e) { setUpdDesc('Couldn’t check for updates.'); if (manual) await askConfirm({ title: 'Couldn’t check', message: '' + e, confirmLabel: 'OK' }); return; }
    const available = update && update.available !== false;
    if (!available) {
      setUpdDesc('You’re on the latest version.');
      if (manual) await askConfirm({ title: 'Up to date', message: 'You’re running the latest version of FamChat.', confirmLabel: 'OK' });
      return;
    }
    const ver = update.version || '';
    setUpdDesc('Update available: ' + ver);
    const ok = await askConfirm({ title: 'Update available', message: 'FamChat ' + ver + ' is ready to install. Update now? FamChat will restart.', confirmLabel: 'Update now' });
    if (!ok) return;
    try {
      setUpdDesc('Downloading…');
      await update.downloadAndInstall(() => {});
      if (T.process && T.process.relaunch) await T.process.relaunch();
    } catch (e) {
      setUpdDesc('Update failed.');
      await askConfirm({ title: 'Update failed', message: '' + e, confirmLabel: 'OK' });
    }
  }
  if (updBtn) updBtn.addEventListener('click', () => checkForUpdate(true));

  async function boot() {
    ensureNotifyPermission();
    try { renderSidebar(await invoke('list_conversations')); } catch (e) { renderSidebar([]); }
    showEmpty();
    // If a family hub is set up, reconnect to it automatically.
    try {
      const haddr = localStorage.getItem('famchat-hub-address');
      if (haddr) {
        hubActive = true;
        activeName = 'Family';
        invoke('connect_hub', {
          address: haddr,
          code: localStorage.getItem('famchat-hub-word') || '',
          name: localStorage.getItem('famchat-hub-name') || '',
          id: deviceId(),
        }).catch(() => {});
      }
    } catch (e) {}
    // A quiet check on launch (only prompts if there's actually an update).
    if (localStorage.getItem('famchat-autoupdate') !== 'off') setTimeout(() => checkForUpdate(false), 3000);
  }
  boot();
})();
