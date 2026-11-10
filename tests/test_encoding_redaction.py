"""Regression tests: redaction must survive Content-Encoding.

The proxy's redaction is an exact byte match on the response body. An
upstream that echoes the credential inside a gzip/deflate body would
hand the agent the secret in a form the raw-byte match cannot see —
the agent just decompresses. These tests pin the fix: the proxy never
forwards the agent's Accept-Encoding, decodes an encoded response
before redacting it, and refuses a response whose encoding it cannot
decode instead of relaying it uninspected.
"""

import gzip
import http.client
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cred_proxy.config import parse_config
from cred_proxy.proxy import _decode_body, serve

SECRET = "test-secret-abcdef"


class CompressingEchoHandler(BaseHTTPRequestHandler):
    """Upstream double that encodes by path, ignoring Accept-Encoding
    (a non-compliant upstream: exactly the case the fix must survive)."""

    received = []

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        type(self).received.append(
            {"path": self.path,
             "accept_encoding": self.headers.get("Accept-Encoding")})
        auth = self.headers.get("Authorization")
        payload = json.dumps({"auth": auth, "path": self.path}).encode()
        encoding = None
        if self.path.startswith("/gzip"):
            payload = gzip.compress(payload)
            encoding = "gzip"
        elif self.path.startswith("/deflate"):
            payload = zlib.compress(payload)
            encoding = "deflate"
        elif self.path.startswith("/stacked"):
            # gzip applied first, then deflate: listed in applied order.
            payload = zlib.compress(gzip.compress(payload))
            encoding = "gzip, deflate"
        elif self.path.startswith("/brotli"):
            payload = b"\x1b\xff" + payload  # not real brotli; undecodable here
            encoding = "br"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


@pytest.fixture()
def upstream():
    CompressingEchoHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), CompressingEchoHandler)
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


def call(proxy, path, headers=None):
    conn = http.client.HTTPConnection(
        "127.0.0.1", proxy.server_address[1], timeout=10)
    all_headers = {"Authorization": "proxy:test"}
    if headers:
        all_headers.update(headers)
    conn.request("GET", path, headers=all_headers)
    resp = conn.getresponse()
    data = resp.read()
    result = (resp.status, dict(resp.getheaders()), data)
    conn.close()
    return result


def test_agent_accept_encoding_is_not_forwarded(proxy):
    call(proxy, "/api/plain", headers={"Accept-Encoding": "gzip, br"})
    seen = CompressingEchoHandler.received[-1]["accept_encoding"]
    assert seen is None or "gzip" not in seen and "br" not in seen


def test_gzip_echo_is_decoded_and_redacted(proxy):
    status, headers, body = call(
        proxy, "/api/gzip", headers={"Accept-Encoding": "gzip"})
    assert status == 200
    assert headers.get("Content-Encoding") is None  # relayed as identity
    assert SECRET.encode() not in body
    assert b"***REDACTED***" in body
    assert json.loads(body)["path"] == "/gzip"


def test_deflate_echo_is_decoded_and_redacted(proxy):
    status, _, body = call(proxy, "/api/deflate")
    assert status == 200
    assert SECRET.encode() not in body
    assert b"***REDACTED***" in body


def test_stacked_encodings_are_decoded_and_redacted(proxy):
    status, headers, body = call(proxy, "/api/stacked")
    assert status == 200
    assert headers.get("Content-Encoding") is None
    assert SECRET.encode() not in body
    assert b"***REDACTED***" in body


def test_undecodable_encoding_fails_closed(proxy):
    status, _, body = call(proxy, "/api/brotli")
    assert status == 502
    assert json.loads(body)["error"] == "uninspectable_response"
    assert SECRET.encode() not in body


def test_plain_response_still_flows(proxy):
    status, _, body = call(proxy, "/api/plain")
    assert status == 200
    assert b"***REDACTED***" in body  # echo redaction unaffected


# -- _decode_body unit checks -------------------------------------------


def test_decode_body_identity_and_empty():
    assert _decode_body(b"abc", None) == b"abc"
    assert _decode_body(b"abc", "identity") == b"abc"
    assert _decode_body(b"", "gzip") == b""  # HEAD/204: nothing to leak


def test_decode_body_rejects_unknown_and_corrupt():
    assert _decode_body(b"abc", "br") is None
    assert _decode_body(b"not-really-gzip", "gzip") is None
    assert _decode_body(gzip.compress(b"abc"), "GZIP") == b"abc"
