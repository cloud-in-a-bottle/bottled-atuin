# bottled-atuin

[Atuin](https://atuin.sh) shell-history sync server packaged as a Cloud in a Bottle
app. The zone owner creates an account from an owner-only `/setup` page in the
browser, then the CLI logs in and syncs using Atuin's own token auth.

## What you get

- atuin-server running on `https://atuin.<zone>/` with TLS terminated by the
  Cloud in a Bottle outer Caddy.
- Only the zone owner can create an account on this server. `/register` and
  `/setup` are not public paths, so the Cloud in a Bottle router only lets
  them through for the authenticated owner.
- All CLI sync paths (`/sync`, `/history`, `/record`, `/api/v0`, etc.) are
  exposed publicly so the CLI can authenticate with its own
  `Authorization: Token <token>` header.
- Persistent state under `/data/app_data/atuin/`:
  - `server.toml` — atuin-server config (rendered on each boot)
  - `atuin.db` — sqlite database with users, sessions, history records

## Configuring your shell

`atuin register` from the CLI does not work against this server: the CLI can't
send Cloud in a Bottle credentials, so the router redirects it to the login page
and the CLI fails with "Server not reporting its version". Create the account
in the browser instead.

1. While logged in to Cloud in a Bottle, open `https://atuin.<zone>/setup`
   (also linked from the dashboard as "Create account") and create an account.
2. On every machine, point Atuin at the server in `~/.config/atuin/config.toml`:

```toml
sync_address = "https://atuin.<zone>"
```

3. On your first machine, generate an encryption key, back it up, and log in.
   Press Enter at the key prompt to use the key you just generated:

```sh
atuin key
atuin login -u <your-username>
atuin sync
```

4. On every other machine, log in with the same key (`atuin key` on the first
   machine prints it):

```sh
atuin login -u <your-username> -k "<your key>"
atuin sync
```

The encryption key never leaves your machines. If you lose it, your synced
history cannot be decrypted.

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
                   - /register, /setup require    │
                     X-OpenHost-Is-Owner; else 403 │
                   - /setup: owner-only form that  │
                     calls /register upstream      │
                   - everything else passes        │
                     through (CLI uses its own     │
                     bearer-token auth)            │
                                                   ▼
                                       127.0.0.1:8888  (atuin-server)
```

## Files

| File              | Purpose                                                     |
| ----------------- | ----------------------------------------------------------- |
| `cloudinabottle.toml` | Cloud in a Bottle manifest (lists CLI paths as public)      |
| `Dockerfile`      | debian:bookworm-slim + downloaded atuin-server prebuilt     |
| `start.sh`        | Renders server.toml, boots atuin-server + auth-proxy        |
| `auth_proxy.py`   | Cloud in a Bottle owner-gate sidecar and `/setup` page      |

## Locking down further

If you want even fewer endpoints reachable from the public internet (e.g.
your shells are all on Tailscale and you're paranoid about CLI endpoints
being scanned), tighten `public_paths` in `cloudinabottle.toml` to just `/healthz`
and reach Atuin from your shells via the Tailscale or zerotier IP of your
Cloud in a Bottle host.
