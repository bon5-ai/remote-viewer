# Changelog

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
