# FamChat

A simple, private chat for the people on your home network.

No accounts, no phone numbers, no cloud. One person starts a chat and shares an
address; everyone else on the same Wi‑Fi joins with a shared family word. Messages,
photos, and files go straight between your devices and never leave your network.
Works on **macOS, Windows, and Linux**.

Want offline messages? FamChat ships with an optional **home‑server hub** — a tiny
always‑on program you run on a spare machine on your network. It acts as a mailbox:
it holds messages for family members who are offline and delivers them when they
come back, so you can message someone even when their FamChat is closed. See
[HUB.md](HUB.md). (No hub, no server — the hub is entirely optional.)

<p align="center"><img src="src-tauri/icons/128x128.png" width="96" alt="FamChat" /></p>

## Download

Grab it from the **[download page](https://nyfeblade.github.io/famchat/)** or the
**[latest release](https://github.com/nyfeblade/famchat/releases/latest)**:

- macOS — `.dmg` (one build for both Apple Silicon and Intel)
- Windows — `.exe` installer
- Linux — `.AppImage` (download, make executable, run) or `.deb`

> FamChat isn't code‑signed yet, so the **first** time you open it macOS or Windows
> shows an "unidentified developer" warning. On a Mac, **right‑click the app → Open**,
> then click **Open**. On Windows, click **More info → Run anyway**. You only do this
> once.

## How it works

1. **One person starts.** Open FamChat, click **+**, choose a **family word**, and
   share the address it shows you (text it, say it — however).
2. **Everyone joins.** The others pick **Join a chat**, paste that address, and type
   the **same family word**.
3. **Chat.** You're connected. Send messages and files; the chat is saved on each
   device so you can scroll back later. Turn on **Group** for more than two people.

You get a desktop notification when a message arrives and FamChat isn't the window
you're looking at.

### Offline messages (optional)

By default everyone has to be online at the same time. If you have a machine that
stays on (a spare laptop, a home server), you can run the **FamChat Hub** on it —
a tiny always-on relay that holds messages for whoever's offline and delivers them
when they reconnect, so you can message someone whose FamChat is closed. It's a
trusted relay on your own network. See **[HUB.md](HUB.md)** to set it up; then in
FamChat use **+ → Family hub**.

## Private by design

- Messages are **end‑to‑end encrypted** in flight (Noise protocol; the family word
  authenticates who gets in via a PAKE, so it's never sent over the wire).
- By default there is **no server** and no account — devices talk directly over
  your LAN. (The optional home hub is the one exception, and it runs on your own
  machine, not anyone else's.)
- History is stored **only on your own device**, and you can wipe it anytime from
  Settings.

FamChat is meant for a trusted home network, not as an anonymity tool. It's a
friendly family chat that happens to keep your conversations to yourselves.

## Build from source

Requires a recent [Rust](https://rustup.rs) toolchain. On Linux you also need the
WebKitGTK dev libraries.

```sh
# Linux build deps (Fedora)
sudo dnf install webkit2gtk4.1-devel gtk3-devel librsvg2-devel

# Linux build deps (Debian/Ubuntu)
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev

# Run it
cargo run -p famchat

# Run the tests
cargo test --workspace
```

Tagging a release (`git tag v0.1.0 && git push --tags`) triggers GitHub Actions to
build the macOS, Windows, and Linux installers and attach them to a Release.

## Layout

```
crates/famchat-core/   the engine: LAN transport, Noise + family-word handshake,
                       message framing, group relay, plaintext history
src-tauri/             the Tauri 2 desktop app (commands, notifications)
ui/                    the front end
docs/                  the download page (served via GitHub Pages)
```

## License

MIT © nyfe
