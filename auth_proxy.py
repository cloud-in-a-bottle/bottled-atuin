"""OpenHost owner-gate auth-proxy for atuin-server.

Sits between the OpenHost router and atuin-server.  Atuin's own
authentication model uses ``Authorization: Token <token>`` headers
that the CLI client sets after registering — the OpenHost router
can't intermediate that, so we list every CLI-consumed path as
``public`` in cloudinabottle.toml.

Only the zone owner can register a new account on this Atuin
server; that is what keeps it effectively single-tenant.  The
non-public paths the proxy gates are /register and /setup.

The atuin CLI can't send Cloud in a Bottle credentials, so
``atuin register`` can never pass the gate.  Instead the proxy serves
an owner-only ``/setup`` page: the owner opens it in a browser (the
router authenticates them with their session cookie), submits a form,
and the proxy calls atuin-server's /register on their behalf.  The
CLI then uses the public ``/login`` endpoint.

Auth model:

  * Owner (X-OpenHost-Is-Owner: true)         → forward unchanged
                                                 (after stripping
                                                 the trust headers).
  * Anonymous + path in PUBLIC_PATH_PREFIXES  → forward unchanged.
                                                 Atuin CLI clients
                                                 carry their own
                                                 Authorization header
                                                 which atuin-server
                                                 validates.
  * Anonymous + other path (e.g. /register)   → 403.  The OpenHost
                                                 router shouldn't
                                                 forward these to us
                                                 anyway, but this
                                                 enforces it as
                                                 defense in depth.

Defense in depth: ALWAYS strip any client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` before forwarding.

Adapted from openhost-pinchflat/auth_proxy.py.
"""

from __future__ import annotations

import html
import http.client
import json
import logging
import os
import selectors
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (OWNER_HEADER_NAME, USER_HEADER_NAME)
)

# Paths the atuin CLI uses with its own ``Authorization: Token``
# header (or, for /login, username + password).  Must stay in sync
# with public_paths in cloudinabottle.toml.  Match by prefix.
PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/healthz",  # OpenHost router liveness probe
    "/login",
    "/sync/",
    "/history",
    "/record",
    "/api/",
    "/user/",
    "/account",
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# Pinchflat downloads videos that may be quite large.  Cap upload
# bodies (POSTs from the UI form) at 100 MiB; downloads to disk go
# via yt-dlp out-of-band, not via this HTTP path.
MAX_BODY_BYTES = 100 * 1024 * 1024

# WebSocket streaming constants.  Phoenix LiveView pushes small
# JSON messages frequently; STREAM_CHUNK_BYTES sized for low
# latency.
STREAM_CHUNK_BYTES = 64 * 1024
STREAM_TIMEOUT_SECONDS = 6 * 60 * 60
HEADER_LINE_CAP = 64 * 1024

# Owner-only account-creation page.  NOT a public path, so the router
# only forwards it with a verified owner identity.
SETUP_PATH = "/setup"
SETUP_MAX_FORM_BYTES = 16 * 1024
SETUP_UPSTREAM_TIMEOUT_SECONDS = 30

_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atuin setup</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
label {{ display: block; margin-top: 1rem; font-weight: 600; }}
input {{ width: 100%; padding: .5rem; font-size: 1rem; box-sizing: border-box; }}
button {{ margin-top: 1.5rem; padding: .6rem 1.2rem; font-size: 1rem; }}
pre {{ background: #f3f3f3; padding: .75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
.error {{ color: #a00; font-weight: 600; }}
</style>
</head>
<body>
<h1>Atuin sync server</h1>
{body}
</body>
</html>
"""

_FORM_TEMPLATE = """
<p>Create an account on this server. Only the owner of this Cloud in a
Bottle instance can see this page. <code>atuin register</code> from the
CLI does not work here, because the CLI cannot send Cloud in a Bottle
credentials.</p>
{error}
<form method="post" action="{action}">
<label for="username">Username</label>
<input id="username" name="username" required autocomplete="username" value="{username}">
<label for="email">Email</label>
<input id="email" name="email" type="email" required autocomplete="email" value="{email}">
<label for="password">Password</label>
<input id="password" name="password" type="password" required autocomplete="new-password">
<button type="submit">Create account</button>
</form>
<h2>Already have an account?</h2>
{client_instructions}
"""

_SUCCESS_TEMPLATE = """
<p>Account <strong>{username}</strong> created.</p>
{client_instructions}
"""

_CLIENT_INSTRUCTIONS_TEMPLATE = """
<p>Point each machine at this server in <code>~/.config/atuin/config.toml</code>:</p>
<pre>sync_address = "{server_url}"</pre>
<p>On your <strong>first</strong> machine, generate an encryption key, back it
up somewhere safe, then log in (press Enter at the key prompt to use the key
you just generated):</p>
<pre>atuin key
atuin login -u {username}
atuin sync</pre>
<p>On every <strong>other</strong> machine, log in with the same key
(<code>atuin key</code> on the first machine prints it):</p>
<pre>atuin login -u {username} -k "&lt;your key&gt;"
atuin sync</pre>
<p>The key never leaves your machines. If you lose it, your synced history
cannot be decrypted.</p>
"""

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _is_public_path(path: str) -> bool:
    # Strip query string for prefix match.
    bare = path.split("?", 1)[0]
    return any(bare.startswith(p) for p in PUBLIC_PATH_PREFIXES)


class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 lets us forward Transfer-Encoding: chunked from upstream
    # untouched and supports Range responses (206) needed for video seeks.
    # Default is HTTP/1.0 which forces a close-per-request and rejects
    # chunked encoding.
    protocol_version = "HTTP/1.1"

    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8888

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path == "/" and self.command == "GET":
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        if not is_owner and not _is_public_path(self.path):
            self._safe_send_error(403, "OpenHost owner required")
            return

        if self.path.split("?", 1)[0].rstrip("/") == SETUP_PATH:
            # Only reachable here as owner: SETUP_PATH is not public.
            self._handle_setup()
            return

        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        self._proxy()

    # ------------------------------------------------------------------
    # Owner-only /setup page
    # ------------------------------------------------------------------

    def _public_origin(self) -> str:
        proto = self.headers.get("X-Forwarded-Proto", "").strip() or "https"
        host = (
            self.headers.get("X-Forwarded-Host", "").strip()
            or self.headers.get("Host", "").strip()
        )
        return f"{proto}://{host}"

    def _send_html(self, status: int, body: str) -> None:
        payload = _PAGE_TEMPLATE.format(body=body).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            # Not "no-referrer": that makes browsers send "Origin: null" on
            # the form POST, which the Origin check below would reject.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except OSError as exc:
            log.debug("client disconnected during setup response: %s", exc)

    def _client_instructions(self, username: str) -> str:
        return _CLIENT_INSTRUCTIONS_TEMPLATE.format(
            server_url=html.escape(self._public_origin()),
            username=html.escape(username or "<username>"),
        )

    def _render_form(
        self, status: int, error: str = "", username: str = "", email: str = ""
    ) -> None:
        body = _FORM_TEMPLATE.format(
            action=SETUP_PATH,
            error=f'<p class="error">{html.escape(error)}</p>' if error else "",
            username=html.escape(username, quote=True),
            email=html.escape(email, quote=True),
            client_instructions=self._client_instructions(""),
        )
        self._send_html(status, body)

    def _handle_setup(self) -> None:
        if self.command in ("GET", "HEAD"):
            self._render_form(200)
            return
        if self.command != "POST":
            self._safe_send_error(405, "Method Not Allowed")
            return

        # The router already rejects cross-origin cookie-authenticated
        # requests; re-check here as defense in depth against CSRF.
        # Browsers send Sec-Fetch-Site on every request, including the
        # rare cases where they omit Origin.
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site not in ("same-origin", "none"):
            log.info("setup: rejecting POST with Sec-Fetch-Site %r", fetch_site)
            self._safe_send_error(403, "cross-origin request rejected")
            return
        origin = self.headers.get("Origin")
        if origin is not None and origin != self._public_origin():
            log.info(
                "setup: rejecting POST with Origin %r (expected %r)",
                origin,
                self._public_origin(),
            )
            self._safe_send_error(403, "cross-origin request rejected")
            return

        if self.headers.get("Transfer-Encoding"):
            self._safe_send_error(501, "Transfer-Encoding not supported on requests")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._safe_send_error(411, "Content-Length required")
            return
        if length < 0 or length > SETUP_MAX_FORM_BYTES:
            self._safe_send_error(413, "request body too large")
            return
        try:
            raw = self.rfile.read(length)
        except (OSError, TimeoutError) as exc:
            log.info("setup form read error: %s", exc)
            self._safe_send_error(400, "request body read failed")
            return
        if len(raw) != length:
            self._safe_send_error(400, "incomplete request body")
            return

        form = urllib.parse.parse_qs(
            raw.decode("utf-8", errors="replace"), keep_blank_values=True
        )
        username = form.get("username", [""])[0].strip()
        email = form.get("email", [""])[0].strip()
        password = form.get("password", [""])[0]
        if not username or not email or not password:
            self._render_form(
                400, "Username, email and password are all required.", username, email
            )
            return

        status, reason = self._register_upstream(username, email, password)
        if status == 200:
            log.info("setup: registered atuin account %r", username)
            self._send_html(
                200,
                _SUCCESS_TEMPLATE.format(
                    username=html.escape(username),
                    client_instructions=self._client_instructions(username),
                ),
            )
            return
        log.info("setup: registration of %r failed (%s): %s", username, status, reason)
        self._render_form(
            400 if 400 <= status < 500 else 502,
            f"Registration failed: {reason}",
            username,
            email,
        )

    def _register_upstream(
        self, username: str, email: str, password: str
    ) -> tuple[int, str]:
        """POST to atuin-server's /register.  Returns (status, reason)."""
        payload = json.dumps(
            {"username": username, "email": email, "password": password}
        ).encode("utf-8")
        conn = http.client.HTTPConnection(
            self.upstream_host,
            self.upstream_port,
            timeout=SETUP_UPSTREAM_TIMEOUT_SECONDS,
        )
        try:
            conn.request(
                "POST",
                "/register",
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "bottled-atuin-setup",
                },
            )
            resp = conn.getresponse()
            body = resp.read(64 * 1024)
        except (OSError, http.client.HTTPException) as exc:
            log.warning("setup: upstream register error: %s", exc)
            return 502, "could not reach atuin-server"
        finally:
            conn.close()

        if resp.status == 200:
            return 200, ""
        try:
            reason = str(json.loads(body).get("reason") or "")
        except (ValueError, AttributeError):
            reason = ""
        return resp.status, reason or f"atuin-server returned HTTP {resp.status}"

    def _is_websocket_upgrade(self) -> bool:
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        connection = self.headers.get("Connection", "").lower()
        connection_tokens = {t.strip() for t in connection.split(",")}
        return upgrade == "websocket" and "upgrade" in connection_tokens

    def _proxy_websocket(self) -> None:
        ws_drop = ALWAYS_STRIP_HEADERS | frozenset({"host"})
        cleaned = _strip_headers(self.headers.items(), ws_drop)
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=STREAM_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            log.warning("upstream connect failed (websocket): %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            upstream_sock.settimeout(STREAM_TIMEOUT_SECONDS)
            host_header = forwarded_host or f"{self.upstream_host}:{self.upstream_port}"
            request_bytes = bytearray()
            request_bytes.extend(
                self._encode_header_bytes(
                    f"{self.command} {self.path} HTTP/1.1\r\n"
                )
            )
            request_bytes.extend(
                self._encode_header_bytes(f"Host: {host_header}\r\n")
            )
            for k, v in cleaned:
                request_bytes.extend(
                    self._encode_header_bytes(f"{k}: {v}\r\n")
                )
            request_bytes.extend(b"\r\n")
            try:
                upstream_sock.sendall(bytes(request_bytes))
            except OSError as exc:
                log.warning("websocket request send failed: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            response_buf = self._read_until_double_crlf(
                upstream_sock, max_bytes=HEADER_LINE_CAP
            )
            if response_buf is None:
                self._safe_send_error(502, "Bad Gateway")
                return
            head_bytes, tail_bytes = response_buf

            try:
                self.wfile.write(head_bytes)
                if tail_bytes:
                    self.wfile.write(tail_bytes)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected during ws handshake: %s", exc)
                return

            if not head_bytes.startswith(b"HTTP/1.1 101"):
                first_line = head_bytes.split(b"\r\n", 1)[0].decode(
                    "latin-1", errors="replace"
                )
                log.info("upstream rejected websocket upgrade: %s", first_line)
                return

            self._websocket_pump(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_until_double_crlf(
        sock: socket.socket, max_bytes: int
    ) -> tuple[bytes, bytes] | None:
        buf = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except OSError as exc:
                log.info("websocket handshake recv failed: %s", exc)
                return None
            if not chunk:
                return None
            buf.extend(chunk)
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                head = bytes(buf[: idx + 4])
                tail = bytes(buf[idx + 4 :])
                return head, tail
            if len(buf) >= max_bytes:
                log.warning(
                    "websocket response head exceeds %d bytes; aborting",
                    max_bytes,
                )
                return None

    @staticmethod
    def _websocket_pump(
        client_sock: socket.socket, upstream_sock: socket.socket
    ) -> None:
        for s in (client_sock, upstream_sock):
            try:
                s.settimeout(None)
            except OSError:
                pass

        sel = selectors.DefaultSelector()
        try:
            sel.register(client_sock, selectors.EVENT_READ, "client")
            sel.register(upstream_sock, selectors.EVENT_READ, "upstream")
            while True:
                events = sel.select(timeout=STREAM_TIMEOUT_SECONDS)
                if not events:
                    log.info("websocket idle timeout; closing")
                    return
                for key, _ in events:
                    if key.data == "client":
                        src, dst = client_sock, upstream_sock
                        direction = "client->upstream"
                    else:
                        src, dst = upstream_sock, client_sock
                        direction = "upstream->client"
                    try:
                        chunk = src.recv(STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        log.info("websocket %s recv failed: %s", direction, exc)
                        return
                    if not chunk:
                        log.debug("websocket %s EOF; closing", direction)
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError as exc:
                        log.info("websocket %s sendall failed: %s", direction, exc)
                        return
        finally:
            try:
                sel.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("websocket selector close failed: %s", exc)

    @staticmethod
    def _encode_header_bytes(value: str) -> bytes:
        try:
            return value.encode("latin-1")
        except UnicodeEncodeError:
            log.warning("non-latin-1 header value, replacing offending bytes")
            return value.encode("latin-1", errors="replace")

    def _proxy(self) -> None:
        """Forward an HTTP request to the upstream and stream the response back.

        We deliberately stream both directions in chunks rather than buffer
        the body — large media / API responses would otherwise OOM the proxy
        or trip a body-size cap and 502 the request.
        """
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )

        # Forward request body if present.  We still cap *requests* at
        # MAX_BODY_BYTES because legitimate UI POSTs are tiny and buffering
        # them keeps the client→upstream side simple; uploads larger than
        # this should use a different code path.
        body: bytes | None = None
        client_te = self.headers.get("Transfer-Encoding", "").lower().strip()
        if client_te and client_te != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported on requests")
            return

        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        # Long timeout so multi-GiB streams aren't capped at 120s.
        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=STREAM_TIMEOUT_SECONDS
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=False,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # ---- Send response headers immediately, before reading body. ----
            #
            # The response body is streamed below.  We forward upstream's
            # Content-Length / Transfer-Encoding so the client knows how to
            # frame the response (fixed-length vs. chunked) and Range
            # responses (206 with ``Content-Range``) work for video seeking.
            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                # Force one-and-done so we don't have to manage HTTP/1.1
                # keep-alive state between requests on the same TCP
                # connection.  Browsers / Caddy / OpenHost's outer router
                # handle close-per-request fine.
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
            except OSError as exc:
                log.debug("client disconnected during response head: %s", exc)
                upstream.close()
                return

            # ---- Stream body in chunks. ----
            if self.command != "HEAD":
                try:
                    while True:
                        chunk = upstream.read(STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except OSError as exc:
                            log.debug(
                                "client disconnected mid-stream after %d bytes: %s",
                                len(chunk), exc,
                            )
                            return
                except (OSError, http.client.HTTPException) as exc:
                    log.warning("upstream read error mid-stream: %s", exc)
                    return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8888)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d",
        listen_port,
        upstream_host,
        upstream_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
