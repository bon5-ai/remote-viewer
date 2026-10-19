# AWS CloudFront in front of Tailscale Funnel

This setup gives you your own domain (`https://term.example.com/`) and edge TLS, and lets
the gate refuse anyone who goes around CloudFront to the Funnel origin directly. Everything
runs in **your** AWS account. The template creates two resources: one CloudFront
distribution and one cache policy.

```
browser / agent ─► CloudFront (adds X-Origin-Verify: <secret>) ─► Funnel (your-machine.ts.net:8443) ─► gate 127.0.0.1:8095
```

## 1. Publish the gate with Funnel

```bash
sudo tailscale funnel --bg --https=8443 http://127.0.0.1:8095
```

## 2. (Optional) a certificate for your domain

For a custom domain, request or import an ACM certificate **in us-east-1**, which is the
region CloudFront reads certificates from. Validate it with DNS. Without a custom domain,
the distribution's own `dxxxx.cloudfront.net` name works.

## 3. Deploy the template

```bash
# Uses your normal AWS credentials (AWS_PROFILE / AWS_REGION).
deploy/aws/deploy.sh remote-viewer your-machine.your-tailnet.ts.net 8443
# or with a custom domain:
deploy/aws/deploy.sh remote-viewer your-machine.your-tailnet.ts.net 8443 term.example.com arn:aws:acm:us-east-1:111122223333:certificate/...
```

`deploy.sh` does three things:

- **Generates the origin secret** into `~/.config/bon5ai-remote/proxy-secret` with mode
  0600. That happens only the first time; later runs reuse it.
- **Hands it to CloudFormation from a temporary 0600 file.** The secret never appears on a
  command line, in your shell history or in `ps`.
- **Prints the stack outputs** and the gate config to use.

If you'd rather use the console or your own IaC, deploy [`cloudfront.yaml`](../../deploy/aws/cloudfront.yaml)
directly. Its parameters are documented inline.

## 4. Configure the gate

```toml
# ~/.config/bon5ai-remote/config.toml
proxy_secret_file = "~/.config/bon5ai-remote/proxy-secret"

[[listener]]
address = "127.0.0.1:8095"
public_url = "https://term.example.com/"          # the PublicUrl output
proxy_header = "X-Origin-Verify"
# CloudFront sends the origin's name as Host, so the gate must accept it:
allowed_hosts = ["your-machine.your-tailnet.ts.net", "your-machine.your-tailnet.ts.net:8443"]
```

```bash
systemctl --user restart tmux-remote-viewer
tmux-remote-viewer doctor
```

With `proxy_header` set and no secret available, the gate refuses to start. It never
runs with the check quietly switched off.

## 5. DNS

Point `term.example.com` at the distribution's domain name, with a CNAME or, in Route 53,
an alias record.

## 6. Check it

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://your-machine.your-tailnet.ts.net:8443/   # 404: no secret
curl -s -o /dev/null -w '%{http_code}\n' https://term.example.com/                         # 200: the viewer page
curl -s https://term.example.com/.well-known/oauth-authorization-server | head -c 200      # agent sign-in metadata
```

If a page answers `421 Misdirected request`, look for the gate's `refused Host '...'`
log line (`journalctl --user -u tmux-remote-viewer`) and add that value to `allowed_hosts`.

## Why the cache policy looks odd

MCP clients send their token in the `Authorization` header. CloudFront forwards that
header only when it is part of the cache key, and a cache key can only include headers
when caching is allowed. The template's cache policy therefore puts `Authorization` in
the key with a maximum TTL of 1 second and a default of 0. The gate marks every response
`Cache-Control: no-store`, so nothing is cached. The managed *AllViewerExceptHostHeader*
origin request policy forwards everything else: cookies, query strings, the MCP headers
and the WebSocket handshake.

Observed in October 2026: a distribution using the managed *CachingDisabled* policy also
delivered `Authorization` to the origin on POST requests, which is all MCP uses. The
template doesn't depend on that behaviour, and its cache policy covers every method.

## Per-client lockouts (optional)

Behind CloudFront and Funnel, every request reaches the gate from 127.0.0.1. Wrong
viewer codes therefore share one limit: 10 in 10 minutes locks pairing for everyone,
including you, until the window passes. To scope the limit to each client instead:

1. Create an origin request policy that forwards all viewer headers except Host, plus the
   `CloudFront-Viewer-Address` header, and use it in place of the managed one.
2. Set `client_ip_header = "CloudFront-Viewer-Address"` on the listener. The gate trusts
   it only on requests that carry the proxy secret.

## Mounting under a path of an existing distribution

To serve the gate at `https://example.com/remote/` from a distribution that already
serves something else:

1. **Funnel:** `sudo tailscale funnel --bg --https=8443 --set-path /remote http://127.0.0.1:8095`.
2. **Origin:** add the Funnel origin, with the secret custom header.
3. **Behavior:** add a `/remote/*` behavior with the cache policy above and
   AllViewerExceptHostHeader. Optionally add a CloudFront Function that redirects
   `/remote` to `/remote/`.
4. **Gate:** set `public_url = "https://example.com/remote/"`.

Agent sign-in still works under a path. Discovery tries the host-root URLs first
(`/.well-known/oauth-authorization-server/remote`), and those should answer **404**, not
your site's HTML. Clients then fall back to `https://example.com/remote/.well-known/openid-configuration`,
which the gate serves. If your default behavior answers every path with a 200 (a
single-page app's fallback), either add behaviors that route those two `/.well-known/*/remote`
paths to the gate, or serve the gate from its own hostname.

## Costs

CloudFront bills per request and per GB transferred, and its free tier covers personal
use comfortably. The template creates no other billable resources.

## Things to know

- **Who can read the secret.** It is stored in the distribution's config. Anyone with
  `cloudfront:GetDistributionConfig` in your account can read it. To rotate it, delete
  the secret file, rerun `deploy.sh`, then restart the gate.
- **Origin timeout.** CloudFront gives the origin 30 seconds by default. That is why the
  MCP `wait_for` and `run_command` tools stop waiting after 25.
- **WebSockets.** CloudFront passes WebSockets through without extra settings. The viewer's
  live stream uses one.
