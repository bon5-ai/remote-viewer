# Behind your own reverse proxy (Caddy, nginx, Cloudflare Tunnel)

The gate works behind any HTTPS proxy that does three things:

- **forwards WebSockets.** The viewer's live stream at `/ws` uses one;
- **forwards the `Authorization` header and doesn't buffer responses** (for `/mcp` and the
  OAuth endpoints);
- **sends a `Host` the gate accepts:** the `public_url` host, or a name listed in
  `allowed_hosts`.

If the proxy runs on the same machine and talks to `127.0.0.1:8095`, you don't need
`proxy_header`: only local processes can reach the gate directly. Use `proxy_header`
when the gate's origin is itself reachable from the internet (as with Funnel) and you want
to refuse requests that skip the proxy.

## Caddy

```caddy
term.example.com {
    reverse_proxy 127.0.0.1:8095
}
```

```toml
[[listener]]
address = "127.0.0.1:8095"
public_url = "https://term.example.com/"
```

Caddy passes `Host` through and handles WebSockets on its own.

## nginx

```nginx
server {
    listen 443 ssl;
    server_name term.example.com;
    # ssl_certificate ... ;

    location / {
        proxy_pass http://127.0.0.1:8095;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_read_timeout 60s;
    }
}

# in the http block:
map $http_upgrade $connection_upgrade { default upgrade; '' close; }
```

## Cloudflare Tunnel

```bash
cloudflared tunnel --url http://127.0.0.1:8095 --hostname term.example.com
```

Set `public_url = "https://term.example.com/"`. If you put Cloudflare Access in front,
exempt `/mcp`, `/token`, `/register`, `/revoke`, `/.well-known/*` and `/jwks.json` from it.
Agents authenticate with the gate's own OAuth, and can't complete an Access login.

## A proxy in a container (Traefik, Docker)

When the proxy runs in Docker and can't reach the host's loopback, bind the gate to the
bridge network's gateway address, and say so explicitly:

```toml
allow_private_listen = true

[[listener]]
address = "172.18.0.1:8095"   # your docker network's gateway
public_url = "https://term.example.com/"
```

The gate refuses public and unspecified addresses (`0.0.0.0`) even with this setting.
Limit which source addresses the proxy accepts (Traefik's `ipAllowList`, for example).
