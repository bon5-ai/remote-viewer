# Changelog

## Unreleased

- **Security.** The commands the gate writes for tmux, the service and Claude Code's
  `headersHelper` run Python with `-P`, so a `bon5ai_remote` package planted in the
  working directory (a cloned repository, say) can no longer be imported in place of the
  installed one. Re-run `agent token` and `install-service` to regenerate them.
- **Security.** Wrong viewer codes no longer lock pairing when the gate can't tell clients
  apart (behind Funnel, every request comes from 127.0.0.1): ten wrong codes used to lock
  everyone out, the owner included, for ten minutes, and anyone could repeat that. Wrong
  answers now wait a second each, a few at a time, and the terminal is told after ten.
  Behind a trusted `client_ip_header` an address is still locked out. The global pause at
  100 wrong codes is gone with it. Pending agent sign-ins follow the same idea: when the
  gate's 10 are taken, the oldest makes room instead of everyone being refused.
- **Security.** The gate trusts the stream's port only while the wrapper `share` started
  is alive and owns it. After asciinema exited, another local user could bind the port and
  the gate would have relayed it, player script included. `share` records the wrapper's
  pid; run it again once after upgrading so the running stream is recorded.
- **Security.** `allow_private_listen` no longer accepts `::ffff:0.0.0.0`, which binds every
  IPv4 interface. A Tailscale address is still accepted; config.example.toml says what that
  means.
- **Security.** `/claim` takes JSON from the viewer page only, every error page carries the
  security headers, a trailing slash is no longer redirected, and the websocket relay sends
  nothing a browser says on to asciinema and no longer trips over a malformed subprotocol.
- **Security.** An authorization code is spent only by an exchange that passes every check,
  so trying a code without its verifier neither burns it nor revokes the grant; an expired
  code replayed later still does. A client name that claims to be verified is dropped, and
  the sign-in page shows the identity line apart from the name. `agent approve` no longer
  picks a lone request on its own when it returns to a hosted callback. Text an agent types
  may not contain a no-break or other non-ASCII space. The metadata fetch's deadline now
  starts before the name lookup.
- `stream.log` is created 0600, and the service units set `UMask=0077`. CI pins its actions
  by commit.
- OAuth and MCP authorization follow the client-metadata and token rules more closely.
  A metadata URL that does not answer is remembered on its own, for a minute; an error
  response or an invalid document is not cached, so one bad URL cannot lock out every
  client on that host. Documents that carry a client secret, and `client_id` URLs with
  `.` or `..` path segments, are refused. `/authorize` rejects a repeated parameter.
  Revoking a token requires the client it was issued to. The 401 challenge names the
  `scope` a sign-in needs, and a resource indicator matches ignoring scheme and host
  case, a default port and a trailing slash. The grant stays bound to this server's own
  MCP URL.
- Dynamic client registration drops redirect URIs it can't allow instead of refusing the
  whole registration, so Grok Bot (which also lists a `cursor://` callback) can sign in.
- Interactive prompts (`share`'s "Press Enter", `agent approve`'s scope, pane and
  confirmation) work again. They opened `/dev/tty` in a mode a terminal can't support,
  so they always failed with "This needs an interactive terminal".
- The pairing code field formats as you type or paste: uppercase, letters and digits
  only, at most 8, with the dash added after the fourth. A short code is caught in the
  page instead of counting as a wrong guess.
- `tmux-remote-viewer code --ttl 30m` sets how long one code lasts, from 1 minute to 1 hour,
  without changing `code_ttl_seconds`.
- On the agent sign-in page, click the approve command or the request ID to copy it.

## 0.1.0 (2026-10-19)

First release, spun out of a personal project where it had been the "remote viewer".

- Read-only browser viewer for a tmux session: one-time pairing codes and QR links,
  asciinema's player, a window-sized stream, and Cascadia Mono.
- MCP endpoint (Streamable HTTP, 2025 and 2026 protocol revisions) with tools to read the
  screen, wait for output, type, press keys and run commands.
- OAuth 2.1 for agents: PKCE, bounded dynamic client registration, Client ID Metadata
  Documents, audience-bound tokens, and rotating refresh tokens. Every agent is approved at
  the terminal, with a scope (observe, suggest, control) and one pane.
- A dedicated tmux server; status-line badges for viewers, agents and pending sign-ins; a
  kill key; an audit log.
- Deployment guides for local use, Tailscale Serve and Funnel, AWS CloudFront (a
  CloudFormation template plus a deploy script) and reverse proxies.
