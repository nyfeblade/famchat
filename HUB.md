# FamChat Hub — offline messages for your family

Normally FamChat is live-only: everyone has to be online at the same time. The
**hub** changes that. It's a tiny, always-on program you run on one machine that
stays on (a spare laptop, a home server). Everyone's FamChat connects to it as the
standing family room, and it **holds messages for whoever's offline** and delivers
them the moment they come back.

The hub is a *trusted* relay: because it stores and forwards messages, it can read
them. Run it on a machine you trust — it's your own family's, on your own network.

## Set up the hub (Linux, e.g. an Ubuntu laptop)

Do this once on the always-on machine.

1. **Put the hub program in place.** Copy the `famchat-hub` binary to
   `~/.local/bin/` and make it executable:
   ```sh
   mkdir -p ~/.local/bin
   cp famchat-hub ~/.local/bin/famchat-hub
   chmod +x ~/.local/bin/famchat-hub
   ```
   (Get `famchat-hub` from the FamChat release assets, or build it with
   `cargo build --release -p famchat-hub`.)

2. **Set your family word.** Create the config file (kept private, mode 0600):
   ```sh
   mkdir -p ~/.config/famchat-hub
   cat > ~/.config/famchat-hub/env <<'EOF'
   FAMCHAT_HUB_WORD=your-family-word
   FAMCHAT_HUB_BIND=0.0.0.0:9000
   EOF
   chmod 600 ~/.config/famchat-hub/env
   ```
   Use the same family word everyone types in FamChat.

3. **Install it as a service so it runs on its own.**
   ```sh
   mkdir -p ~/.config/systemd/user
   cp famchat-hub.service ~/.config/systemd/user/famchat-hub.service
   systemctl --user daemon-reload
   systemctl --user enable --now famchat-hub
   # keep it running even when no one is logged in:
   sudo loginctl enable-linger "$USER"
   ```
   Check it's up: `systemctl --user status famchat-hub` (and
   `journalctl --user -u famchat-hub -f` to watch it).

4. **Open the port** if you use a firewall:
   ```sh
   sudo ufw allow 9000/tcp   # only if ufw is enabled
   ```

5. **Find the hub's address.** On the hub machine:
   ```sh
   hostname -I        # e.g. 192.168.1.50
   ```
   The hub address your family enters is that IP plus the port, e.g.
   `192.168.1.50:9000`.

## Point FamChat at the hub (on every device)

In FamChat: click **+ → Family hub**, then enter:

- **Hub address** — the address from step 5 (e.g. `192.168.1.50:9000`)
- **Family word** — the same word as the hub
- **Your name** — what the family sees

Click **Connect**. FamChat remembers it and reconnects automatically every launch.
You'll receive anything sent while you were away, and you can message someone whose
FamChat is closed — they'll get it when they reopen it (as long as the hub is on).

To stop using the hub on a device, open the chat and hit the leave button →
**Disconnect**.

## Good to know

- If the hub machine is off, you're back to live-only until it's back on.
- The hub only reaches devices on your own network — it's a home mailbox, not a
  cloud one.
- Messages are encrypted between each device and the hub; the hub itself (your
  trusted machine) can read them, which is what lets it hold them for later.
