# Tailscale: Serve (your tailnet) and Funnel (the internet)

[Tailscale](https://tailscale.com) gives the gate an HTTPS name, `your-machine.your-tailnet.ts.net`,
with a valid certificate and no ports opened on your router. The gate itself stays on loopback.

| Mode | Who can reach it | Use it for |
|---|---|---|
| **Serve** | devices on your tailnet | agents and viewers on your own devices (recommended for agents) |
| **Funnel** | anyone on the internet | viewing from any phone; agents hosted in the cloud |

Everything on the gate still needs either a viewer code or an agent approval. Funnel
widens who can *try*, not who gets in.

## Serve (tailnet only)

```bash
tailscale serve --bg --https=443 http://127.0.0.1:8095
```

```toml
# ~/.config/bon5ai-remote/config.toml
[[listener]]
address = "127.0.0.1:8095"
public_url = "https://your-machine.your-tailnet.ts.net/"
deny_funnel = true      # refuse anything that arrives through Funnel by mistake
```

Agents on any tailnet device:

```bash
claude mcp add --transport http bon5ai-remote https://your-machine.your-tailnet.ts.net/mcp
```

## Funnel (public)

Funnel serves on ports 443, 8443 and 10000 only. With `--set-path`, it strips that path
before proxying.

```bash
# The gate at the root of port 8443:
sudo tailscale funnel --bg --https=8443 http://127.0.0.1:8095
```

```toml
[[listener]]
address = "127.0.0.1:8095"
public_url = "https://your-machine.your-tailnet.ts.net:8443/"
```

To mount the gate under a path instead (`tailscale funnel --bg --https=8443 --set-path /remote http://127.0.0.1:8095`),
set `public_url = "https://your-machine.your-tailnet.ts.net:8443/remote/"`. The gate accepts
paths with or without the prefix.

How Funnel behaves, observed with Tailscale 1.102 (October 2026):

- it strips the `--set-path` prefix before proxying;
- it adds `Tailscale-Funnel-Request: ?1` and `X-Forwarded-For`;
- it drops any `Tailscale-User-*` headers a visitor tries to forge;
- every request reaches the gate from 127.0.0.1, so the gate can't tell visitors apart by
  address. Wrong viewer codes therefore count against one shared limit unless you put
  CloudFront in front ([aws-cloudfront.md](aws-cloudfront.md)) and set `client_ip_header`.

### Funnel plus a tailnet-only agent listener

A public viewer and a private agent endpoint can run side by side:

```bash
sudo tailscale funnel --bg --https=8443 http://127.0.0.1:8095
tailscale serve --bg --https=8444 http://127.0.0.1:8096
```

```toml
[[listener]]               # public: viewer only
address = "127.0.0.1:8095"
public_url = "https://your-machine.your-tailnet.ts.net:8443/"
mcp = false

[[listener]]               # tailnet: agents only
address = "127.0.0.1:8096"
public_url = "https://your-machine.your-tailnet.ts.net:8444/"
viewer = false
deny_funnel = true
```

## Notes

- **Ports 443 and 8443 can be taken.** If another web server (Traefik, nginx) owns 443 on
  every interface, `tailscale serve --https=443` takes the tailnet IP's 443 away from it.
  Use 8443 or 10000.
- **Your ts.net name is public.** It appears in certificate transparency logs. That is
  harmless here (everything needs a code or an approval), but it is the reason to put a
  proxy secret in front if you use CloudFront.
