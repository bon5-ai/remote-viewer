# Threat model

## What is being protected

- **The terminal session.** What it shows: output, files that are `cat`ed, secrets typed
  where they echo. And what can be typed into it, since that is the person's shell.
- **The person's control of it:** knowing who is watching or typing, and being able to stop them.

## Who is involved

| Actor | Trusted with |
|---|---|
| The person at the terminal (the gate's Unix user) | everything. They mint codes, approve agents and revoke. |
| A paired browser | read-only viewing of one session, until it ends or 12 hours pass |
| A paired agent | the scope and pane the person approved, until it is revoked or expires, the session ends, or the gate restarts |
| Anyone who can reach the public URL | nothing. They can load the pairing page and start a sign-in. |
| Other local Unix users | nothing. Runtime files are 0700/0600, and the admin socket checks the peer's uid on Linux. |

## Controls

| Threat | Control |
|---|---|
| Guessing a viewer code | 8 characters from a 31-letter alphabet (about 40 bits), used once, valid 10 minutes. 10 wrong codes in 10 minutes block the client: everyone when clients can't be told apart, one address behind a trusted `client_ip_header`. 100 wrong codes in total pause pairing and tell the terminal. |
| Codes leaking through logs | The QR link carries the code in the URL fragment, which browsers never send. The page then removes it from the address bar. |
| Stealing a viewer or agent session | Every token is random, 256 bits, stored as a SHA-256 digest in memory only. Cookies are HttpOnly, Secure, SameSite=Strict and directory-scoped. A viewer is bound to its session: once that session ends, its cookie can't open the stream or the player, even if a new session has started. |
| An agent signing itself in | Approval needs the admin socket (a 0700 directory, a 0600 socket, the peer uid checked), so it takes a shell as this user. No public route grants anything. |
| A phished approval (an attacker starts a sign-in and asks you to approve it) | The sign-in page and `agent approve` both show the same request ID. You are told to approve only IDs on pages you opened. Redirects go only to localhost or an explicit allowlist, so the auth code lands on the machine that opened the page. PKCE keeps a stolen code useless. |
| A stolen or replayed auth code or refresh token | A code is used once, lives 60 s, and is bound to its client, redirect URI, PKCE challenge and resource. A replayed code revokes the grant. Refresh tokens rotate. A retry within 30 s gets the same new pair, never a second chain; reuse after that revokes the grant. Each grant keeps at most 5 tokens of each kind. |
| A token used against another server or URL | Tokens are audience-bound (RFC 8707) to the exact MCP URL they were issued for, and checked on every call. |
| Scope escalation | Scope comes from the approval only. The tool list is filtered by scope, and calls are checked again. |
| An agent typing somewhere unexpected | The grant is pinned to a pane in its own session. Writes are refused when that pane is gone, in copy mode or not on screen, when the person typed in the last 2 s, or when the screen changed since the agent read it (`if_screen`). `run_command` clears the input line first, and presses Enter only once that line shows the command as typed. |
| Escape and flag injection when typing | `send-keys -l --`, with the trailing `;` escaped for tmux's parser. ESC, all C0 and C1 controls, DEL, line separators, and bidi and zero-width characters are refused. Named keys come from an allowlist without C-s and C-q. Pastes use private single-use buffers. |
| `run_command` returning early, so the agent types into a running program | Done means the foreground process group is the shell again **and** the screen has settled since it changed. |
| `suggest` getting something to run without Enter | Text only, with no Tab (completion can run code), and only while a known local shell owns the terminal and no full-screen program is up. |
| DNS rebinding against a local listener | Every request's Host header must be the public host, a loopback address on that port, or an explicit `allowed_hosts` entry. `/mcp` and `/ws` also check `Origin`. |
| Bypassing the proxy (reaching the Funnel origin directly) | `proxy_header` plus a secret. Requests without it get a 404. With the header configured and no secret available, the gate refuses to start. |
| Abuse of unauthenticated endpoints | Registrations are capped at 100. When the cap is full, the least recently used registration that has no grant or sign-in in progress is forgotten, so a flood can neither fill the table nor lock registration. Unused registrations are forgotten after a week. Pending sign-ins are capped at 10 (3 per client). Request bodies are capped, and client names are cleaned of control and bidi characters, as are tmux's pane and window names. |
| SSRF through Client ID Metadata Documents | https only, with a real path and no `.` or `..` segments. Every resolved address must be public, including any IPv4 address embedded in an IPv6 one (mapped, 6to4, Teredo, NAT64). The connection is pinned to the checked address. No redirects, a 64 KB cap, and a single 5 s deadline for the whole fetch, enforced by a watchdog. A document that carries a client secret is refused. |
| Starving the gate with slow metadata servers | Metadata fetches run in their own pool of 4 threads, separate from the requests the gate serves. A URL that does not answer isn't fetched again for a minute. Error responses and invalid documents are not cached, so one bad URL cannot block the rest of its host. |
| Someone else revoking a token | `/revoke` ends a grant only when `client_id` is the client the token was issued to. An unknown token gets an empty 200. A token from `agent token` has no OAuth client, so whoever holds it can end it. |
| Clickjacking, script injection | A strict CSP with `frame-ancestors 'none'`. The sign-in page has no inline script and renders values with `textContent`. |
| Not noticing | The status line shows viewers, agents and pending sign-ins. `prefix + X` revokes every agent. An append-only 0600 audit log records approvals, revocations and every write with its text. |

## What this does not protect against

- **An agent that already has a shell as your user.** It can run `tmux` itself. Pairing on
  the same machine records consent and limits scope, but it does not isolate anything. Run
  agents somewhere the tmux socket isn't reachable (a container, a sandbox, another user,
  another machine) for `/mcp` to be the only way in.
- **What `control` means.** `control` is your shell. A control agent can do anything you
  can: turn off the status line, unbind the kill key, or approve another agent through the
  admin socket. Revoking still works from any other shell, because the gate checks every
  call. Grant `observe` or `suggest` when that is enough.
- **What "at a prompt" can't see.** It means a known shell owns the terminal. A shell
  builtin that reads one key, such as `read -n1` or zsh's correction prompt, looks the same,
  and so does readline's vi command mode. That's one more reason `suggest` is for a person
  who is watching.
- **Prompt injection.** Anything on screen reaches the agent's model, and anything that
  reaches a model can steer it. Results are marked as untrusted, and the server's
  instructions say so, but that is advice to the model, not enforcement. Don't give
  `control` to an agent while untrusted content is on screen.
- **Where read access sends data.** `observe` sends the screen to the agent's model
  provider. Don't show secrets while sharing.
- **Command allowlists.** There are none, on purpose. They are easy to get around: type
  one character at a time, use aliases, `$(…)`, base64, or a REPL.
- **Other users on the same host.** asciinema's local stream server (127.0.0.1, random
  port) has no authentication. Any local user who finds the port can watch.
  `tmux-remote-viewer doctor` warns when other users are logged in.
- **Who can read the CloudFront secret.** Anyone who can read the distribution's config in
  your AWS account can read the origin secret.
- **Hosted OAuth clients.** A web chat's shared callback in `allowed_redirect_uris` means
  any user of that service can start a sign-in. The request ID check is the only defence.
- **Plain HTTP on loopback.** Reached as `127.0.0.1`, `localhost` or `[::1]`, the issuer
  and its endpoints are `http://`. Anywhere else, `public_url` has to be https.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
