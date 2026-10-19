# Service files

`bon5ai-remote install-service` writes one of these for you, with the path of the
installed command filled in. These copies are for people who'd rather install by hand.

- `systemd/bon5ai-remote.service`: a systemd **user** unit. Copy it to
  `~/.config/systemd/user/`, then run `systemctl --user daemon-reload && systemctl --user enable --now bon5ai-remote`.
  Run `loginctl enable-linger $USER` to keep it running while you are logged out. The
  proxy secret, if you use one, goes in `~/.config/bon5ai-remote/env` (mode 0600) as
  `BON5AI_REMOTE_PROXY_SECRET=...`, or in a file named by `proxy_secret_file`.
- `launchd/ai.bon5.remote-viewer.plist`: a launchd agent for macOS. Copy it to
  `~/Library/LaunchAgents/`, then run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.bon5.remote-viewer.plist`.
