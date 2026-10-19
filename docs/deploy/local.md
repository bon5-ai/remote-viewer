# Local only

The simplest setup is the gate on loopback. Browsers and agents on the same machine
reach it at `http://127.0.0.1:8095/`, and nothing is published.

```bash
tmux-remote-viewer install-service --enable   # or: tmux-remote-viewer serve
tmux-remote-viewer share
```

There is no config file and no secret. The default listener is `127.0.0.1:8095`, with
`public_url = "http://127.0.0.1:8095/"`.

## Agents on the same machine

**Claude Code, with OAuth sign-in:**

```bash
claude mcp add --transport http tmux-remote-viewer http://127.0.0.1:8095/mcp
```

1. In Claude Code, run `/mcp`, pick `tmux-remote-viewer` and choose Authenticate. A browser page opens and shows a request ID.
2. In a shell, run `tmux-remote-viewer agent approve <ID>`.

OAuth allows plain http for loopback addresses, so no certificate is needed.

**No browser, or `claude -p`, the Agent SDK or CI.** These clients can't complete OAuth.
Mint a grant whose token is read by a helper instead:

```bash
tmux-remote-viewer agent token --scope observe --label "ci" --out ~/.config/bon5ai-remote/ci.token
# prints the matching `claude mcp add-json ... headersHelper ...` line
```

The token never appears on screen or in the Claude Code config. Claude Code runs
`tmux-remote-viewer agent headers <file>` each time it connects.

## What "local" does and doesn't protect

Any process running as your user can already run `tmux -S <socket> send-keys`. Pairing
on the same machine therefore records consent and limits scope, but it does not isolate
anything. The real boundary appears when the agent runs somewhere the tmux socket isn't
reachable: a container, a sandbox, another user, or another machine. Then `/mcp` is its
only way in. See [the threat model](../threat-model.md).

On a machine shared with other users, keep in mind that asciinema's stream port on
127.0.0.1 has no authentication. `tmux-remote-viewer doctor` warns when other users are
logged in.
