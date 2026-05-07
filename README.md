# openhost-atuin

[Atuin](https://atuin.sh) shell-history sync server packaged as an OpenHost
app. The zone owner registers their atuin client once via the OpenHost-gated
`/register` endpoint, then the CLI sync uses Atuin's own bearer-token auth
directly.

## What you get

- atuin-server running on `https://atuin.<zone>/` with TLS terminated by the
  OpenHost outer Caddy.
- Only the zone owner can register a new account on this server (the
  OpenHost router gates `/register` on a verified owner JWT).
- All CLI sync paths (`/sync`, `/history`, `/record`, `/api/v0`, etc.) are
  exposed publicly so the CLI can authenticate with its own
  `Authorization: Token <token>` header.
- Persistent state under `/data/app_data/atuin/`:
  - `server.toml` — atuin-server config (rendered on each boot)
  - `atuin.db` — sqlite database with users, sessions, history records

## Configuring your shell

After deploying:

1. Visit `https://atuin.<zone>/` in your browser to confirm it's reachable.
2. On your shell client run:

```sh
atuin register \
  --server-url https://atuin.<zone> \
  --username <your-username> \
  --email <your-email> \
  --password <your-password>
```

   Atuin's CLI will hit `https://atuin.<zone>/register` and the OpenHost
   router will check that you're the zone owner before letting it through.
3. The CLI saves a session token under `~/.local/share/atuin/session`. From
   then on, sync just works:

```sh
atuin sync
```

4. On a second device, install Atuin and:

```sh
atuin login \
  --server-url https://atuin.<zone> \
  --username <your-username> \
  --password <your-password> \
  --key "<the encryption key you got at registration>"
atuin sync -f
```

## Architecture

```
browser / CLI
   │
   ▼
OpenHost outer Caddy (TLS)
   │
   ▼
OpenHost router (only stamps X-OpenHost-Is-Owner: true on owner JWTs;
                  allows public_paths through unauthenticated)
   │
   ▼
container :8080  ── auth_proxy.py ─────────────────┐
                   - /register requires           │
                     X-OpenHost-Is-Owner; else 403 │
                   - everything else passes        │
                     through (CLI uses its own     │
                     bearer-token auth)            │
                                                   ▼
                                       127.0.0.1:8888  (atuin-server)
```

## Files

| File              | Purpose                                                     |
| ----------------- | ----------------------------------------------------------- |
| `openhost.toml`   | OpenHost manifest (lists CLI paths as public)               |
| `Dockerfile`      | debian:bookworm-slim + downloaded atuin-server prebuilt     |
| `start.sh`        | Renders server.toml, boots atuin-server + auth-proxy        |
| `auth_proxy.py`   | OpenHost owner-gate sidecar                                 |

## Locking down further

If you want even fewer endpoints reachable from the public internet (e.g.
your shells are all on Tailscale and you're paranoid about CLI endpoints
being scanned), tighten `public_paths` in `openhost.toml` to just `/healthz`
and reach Atuin from your shells via the Tailscale or zerotier IP of your
OpenHost host.
