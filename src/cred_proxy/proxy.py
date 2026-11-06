"""The egress proxy itself.

An agent sends requests to the proxy with a placeholder header value such
as ``proxy:openai``. For a declared route the proxy swaps the placeholder
for the real credential, rendered through the route's template, and
forwards the request to the route's fixed upstream. Undeclared routes and
undeclared credentials are refused without any upstream call, and the real
secret is redacted out of anything the upstream sends back.
"""

from __future__ import annotations

import http.client
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import Config
from .secrets import SecretStore, redact_bytes, redact_text

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
}

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def validate_bind(host: str, allow_remote: bool) -> None:
    """Refuse a non-loopback bind unless the operator explicitly allows it."""
    if host in LOOPBACK_HOSTS or allow_remote:
        return
    raise ValueError(
        f"refusing to bind {host!r}: this proxy handles real credentials. "
        "Bind 127.0.0.1, or pass --allow-remote if you really mean to expose it."
    )


class AuditLog:
    """Append-only record of what the proxy did. Never contains secrets."""

    def __init__(self, path: str | None = None):
        self.entries: list[dict] = []
        self._path = path
        self._lock = threading.Lock()

    def record(self, entry: dict) -> None:
        with self._lock:
            self.entries.append(entry)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, config: Config, store: SecretStore, audit: AuditLog):
        self.config = config
        self.store = store
        self.audit = audit
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # keep stderr clean
        pass

    # -- request handling -------------------------------------------------
    def _handle(self):
        server: ProxyServer = self.server  # type: ignore[assignment]
        parsed = urlparse(self.path)
        match = server.config.route_for_path(parsed.path)
        if match is None:
            self._refuse(403, "undeclared_route", None,
                         "no declared route matches this path")
            return
        route, rest = match

        presented = self.headers.get(route.header)
        if presented is None or presented.strip() != route.placeholder:
            self._refuse(403, "credential_not_authorized", route.name,
                         f"header {route.header} must carry the placeholder "
                         f"{route.placeholder!r} for this route")
            return

        try:
            secret = server.store.resolve(route.credential)
        except Exception as exc:
            self._refuse(500, "credential_unavailable", route.name, str(exc))
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._refuse(400, "bad_request", route.name,
                         "invalid Content-Length header")
            return
        body = self.rfile.read(length) if length > 0 else b""

        upstream = urlparse(route.upstream)
        target = upstream.path.rstrip("/") + rest
        if parsed.query:
            target += "?" + parsed.query

        headers = {}
        for key, value in self.headers.items():
            lk = key.lower()
            if lk in HOP_BY_HOP or lk in ("host", "content-length"):
                continue
            if lk == route.header.lower():
                continue  # replaced below with the real credential
            headers[key] = value
        headers[route.header] = route.template.replace("{secret}", secret)
        if length > 0:
            headers["Content-Length"] = str(len(body))

        conn_cls = (http.client.HTTPSConnection if upstream.scheme == "https"
                    else http.client.HTTPConnection)
        conn = conn_cls(upstream.hostname, upstream.port, timeout=30)
        try:
            conn.request(self.command, target,
                         body=body if length > 0 else None, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_headers = resp.getheaders()
            status = resp.status
        except Exception as exc:
            self._refuse(502, "upstream_error", route.name, str(exc))
            return
        finally:
            conn.close()

        # Nothing the upstream says may hand the secret back to the agent.
        resp_body = redact_bytes(resp_body, [secret])
        self.send_response(status)
        for key, value in resp_headers:
            lk = key.lower()
            if lk in HOP_BY_HOP or lk == "content-length":
                continue
            self.send_header(key, redact_text(value, [secret]))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp_body)

        server.audit.record({
            "time": _utc_now(), "route": route.name, "method": self.command,
            "path": rest, "credential": route.credential, "status": status,
            "result": "forwarded",
        })

    def _refuse(self, status: int, code: str, route_name, message: str):
        server: ProxyServer = self.server  # type: ignore[assignment]
        payload = json.dumps({"error": code, "message": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        server.audit.record({
            "time": _utc_now(), "route": route_name, "method": self.command,
            "path": urlparse(self.path).path, "credential": None,
            "status": status, "result": code,
        })

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


def serve(config: Config, host: str = "127.0.0.1", port: int = 8765,
          allow_remote: bool = False,
          audit_path: str | None = None) -> ProxyServer:
    """Build (but do not start) a proxy server; fails fast on bad secrets."""
    validate_bind(host, allow_remote)
    store = SecretStore(config.credentials)
    store.resolve_all()  # a declared credential must be resolvable up front
    return ProxyServer((host, port), config, store, AuditLog(audit_path))
