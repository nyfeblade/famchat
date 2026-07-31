  if (location.hash.includes('dark')) document.documentElement.setAttribute('data-theme','dark');
  if (location.hash.includes('light')) document.documentElement.setAttribute('data-theme','light');

  const convos = [
    { name:"Family Room", initial:"F", grad:"linear-gradient(150deg,#22a06b,#1c8a5c)", preview:"Mom: dinner at 6!", time:"09:41", online:true, active:true, unread:0 },
    { name:"Mom", initial:"M", grad:"linear-gradient(150deg,#9160a0,#8a5a86)", preview:"see you tonight", time:"09:12", online:true, unread:2 },
    { name:"Dad", initial:"D", grad:"linear-gradient(150deg,#5678a0,#4f6c90)", preview:"You: sending the photos now", time:"TUE", online:false, unread:0 },
    { name:"Kids", initial:"K", grad:"linear-gradient(150deg,#3f9a8c,#3e8e82)", preview:"can we get pizza", time:"MON", online:false, unread:0 },
  ];

  document.getElementById('convoList').innerHTML =
    '<div class="list-label label">Chats</div>' +
    convos.map(c => `
      <div class="convo ${c.active?'active':''}">
        <div class="tile" style="background:${c.grad}">${c.initial}${c.online?'<span class="presence"></span>':''}</div>
        <div class="convo-body">
          <div class="convo-top">
            <div class="convo-name">${c.name}</div>
            ${c.unread?`<div class="convo-count">${c.unread}</div>`:''}
          </div>
          <div class="convo-bottom">
            <div class="convo-preview">${c.preview}</div>
          </div>
        </div>
      </div>`).join('');

  const fileSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6"/></svg>';
  const AV = ['#5678a0','#3f9a8c','#9160a0','#b8724f','#c1913f','#4f6c90'];
  const avatarFor = (n) => { let h = 0; for (let i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) >>> 0; return AV[h % AV.length]; };

  const groups = [
    { day:"Today" },
    { who:"them", label:"Mom", items:[ { text:"Hey everyone — dinner's at 6 tonight." }, { text:"Grandma's coming over too 🙂" } ], time:"09:38" },
    { who:"me", label:"You", items:[ { text:"Sounds good, I'll be there." }, { file:{ name:"grocery-list.pdf", size:"42 KB" } } ], time:"09:39" },
    { who:"them", label:"Dad", items:[ { text:"Can someone grab bread on the way home?" } ], time:"09:40" },
    { who:"me", label:"You", items:[ { text:"On it." } ], time:"09:41" },
    { who:"them", label:"Mom", items:[ { text:"dinner at 6!" } ], time:"09:41" },
    { who:"them", label:"Dad", typing:true, time:"" },
  ];

  document.getElementById('messages').innerHTML = groups.map(g => {
    if (g.day) return `<div class="day"><span>${g.day}</span></div>`;
    const me = g.who === 'me';
    const bg = me ? '#22a06b' : avatarFor(g.label);
    const avatar = `<div class="msg-avatar"><div class="tile" style="background:${bg}">${g.label.charAt(0)}</div></div>`;
    const head = `<div class="msg-head"><span class="msg-name">${g.label}</span><span class="msg-time">${g.time || ''}</span></div>`;
    const body = g.typing
      ? `<div class="msg-line typing"><div class="dots"><span></span><span></span><span></span></div></div>`
      : g.items.map(it => it.file
          ? `<div class="filecard"><div class="file-ic">${fileSvg}</div><div class="file-meta"><div class="fname">${it.file.name}</div><div class="fsize">${it.file.size}</div></div></div>`
          : `<div class="msg-line">${it.text}</div>`).join('');
    return `<div class="msg first ${g.who}">${avatar}<div class="msg-content">${head}${body}</div></div>`;
  }).join('');
