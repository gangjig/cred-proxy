import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cred_proxy.config import parse_config
from cred_proxy.proxy import serve, validate_bind

SECRET = "test-secret-abcdef"


class EchoHandler(BaseHTTPRequestHandler):
    """Upstream double: records requests, echoes the auth header back."""

    received = []

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        auth = self.headers.get("Authorization")
        type(self).received.append(
            {"method": self.command, "path": self.path, "auth": auth,
             "body": body})
        status = 201 if self.path.startswith("/created") else 200
        payload = json.dumps({"auth": auth, "path": self.path}).encode()
        self.send_response(status)
        if self.path.startswith("/echo-header"):
            self.send_header("X-Upstream-Auth", auth or "")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle


@pytest.fixture()
def upstream():
    EchoHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture()
def proxy(upstream, monkeypatch):
    monkeypatch.setenv("TEST_KEY", SECRET)
    config = parse_config({
        "credentials": {"test": {"env": "TEST_KEY"}},
        "routes": [{"name": "api",
                    "upstream": f"http://127.0.0.1:{upstream}",
                    "credential": "test"}],
    })
    server = serve(config, host="127.0.0.1", port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


def call(proxy, method, path, auth=None, body=None):
    conn = http.client.HTTPConnection(
        "127.0.0.1", proxy.server_address[1], timeout=10)
    headers = {}
    if auth is not None:
        headers["Authorization"] = auth
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    result = (resp.status, dict(resp.getheaders()), data)
    conn.close()
    return result


def test_placeholder_swapped_for_real_secret(proxy):
    status, _, _ = call(proxy, "GET", "/api/v1/models", auth="proxy:test")
    assert status == 200
    assert EchoHandler.received[-1]["auth"] == f"Bearer {SECRET}"


def test_secret_redacted_from_response_body(proxy):
    _, _, body = call(proxy, "GET", "/api/v1/models", auth="proxy:test")
    assert SECRET.encode() not in body
    assert b"***REDACTED***" in body


def test_secret_redacted_from_response_header(proxy):
    _, headers, _ = call(proxy, "GET", "/api/echo-header", auth="proxy:test")
    assert SECRET not in headers["X-Upstream-Auth"]
    assert "***REDACTED***" in headers["X-Upstream-Auth"]


def test_undeclared_route_refused_without_upstream_call(proxy):
    status, _, body = call(proxy, "GET", "/nope/x", auth="proxy:test")
    assert status == 403
    assert json.loads(body)["error"] == "undeclared_route"
    assert EchoHandler.received == []


def test_wrong_placeholder_refused_without_upstream_call(proxy):
    status, _, body = call(proxy, "GET", "/api/v1/models", auth="proxy:other")
    assert status == 403
    assert json.loads(body)["error"] == "credential_not_authorized"
    assert EchoHandler.received == []


def test_missing_header_refused(proxy):
    status, _, _ = call(proxy, "GET", "/api/v1/models")
    assert status == 403
    assert EchoHandler.received == []


def test_raw_secret_as_header_is_not_forwarded(proxy):
    # Even presenting the real secret directly must not work: only the
    # declared placeholder is accepted, so a leaked key gains nothing here.
    status, _, _ = call(proxy, "GET", "/api/v1/models", auth=f"Bearer {SECRET}")
    assert status == 403
    assert EchoHandler.received == []


def test_path_and_query_forwarded(proxy):
    call(proxy, "GET", "/api/items?page=2&size=5", auth="proxy:test")
    assert EchoHandler.received[-1]["path"] == "/items?page=2&size=5"


def test_post_body_forwarded(proxy):
    status, _, _ = call(proxy, "POST", "/api/submit", auth="proxy:test",
                        body=b"hello-body")
    assert status == 200
    assert EchoHandler.received[-1]["body"] == b"hello-body"
    assert EchoHandler.received[-1]["method"] == "POST"


def test_status_passthrough(proxy):
    status, _, _ = call(proxy, "GET", "/api/created", auth="proxy:test")
    assert status == 201


def test_route_root_forwarded(proxy):
    status, _, _ = call(proxy, "GET", "/api", auth="proxy:test")
    assert status == 200
    assert EchoHandler.received[-1]["path"] == "/"


def test_audit_log_records_without_secret(proxy):
    call(proxy, "GET", "/api/v1/models", auth="proxy:test")
    call(proxy, "GET", "/nope", auth="proxy:test")
    entries = proxy.audit.entries
    assert [e["result"] for e in entries] == ["forwarded", "undeclared_route"]
    assert entries[0]["credential"] == "test"
    assert entries[0]["status"] == 200
    assert SECRET not in json.dumps(entries)


def test_serve_fails_fast_when_secret_missing(upstream, monkeypatch):
    monkeypatch.delenv("TEST_KEY", raising=False)
    config = parse_config({
        "credentials": {"test": {"env": "TEST_KEY"}},
        "routes": [{"name": "api",
                    "upstream": f"http://127.0.0.1:{upstream}",
                    "credential": "test"}],
    })
    with pytest.raises(Exception, match="not set"):
        serve(config, host="127.0.0.1", port=0)


def test_validate_bind_loopback_ok():
    validate_bind("127.0.0.1", allow_remote=False)
    validate_bind("localhost", allow_remote=False)


def test_validate_bind_remote_refused_by_default():
    with pytest.raises(ValueError, match="refusing to bind"):
        validate_bind("0.0.0.0", allow_remote=False)


def test_validate_bind_remote_allowed_explicitly():
    validate_bind("0.0.0.0", allow_remote=True)
