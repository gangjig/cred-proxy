"""Command line interface for cred-proxy.

Commands:
  check   validate a config file and list the permissions it declares
  serve   run the proxy
  demo    self-contained demonstration against a throwaway echo upstream
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import ConfigError, load_config, parse_config
from .proxy import serve
from .secrets import SecretError, SecretStore, mask

DEMO_SECRET = "demo-secret-1234567890"


def _cmd_check(args) -> int:
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}")
        return 1
    store = SecretStore(config.credentials)
    ok = True
    for name in sorted(config.credentials):
        try:
            value = store.resolve(name)
            print(f"credential {name}: resolvable ({mask(value)})")
        except SecretError as exc:
            print(f"credential {name}: NOT resolvable - {exc}")
            ok = False
    for route in config.routes.values():
        print(f"route /{route.name} -> {route.upstream} "
              f"(header {route.header}, credential {route.credential}, "
              f"placeholder {route.placeholder!r})")
    return 0 if ok else 1


def _cmd_serve(args) -> int:
    try:
        config = load_config(args.config)
        server = serve(config, host=args.host, port=args.port,
                       allow_remote=args.allow_remote,
                       audit_path=args.audit_log)
    except (ConfigError, ValueError, SecretError) as exc:
        print(f"cannot start: {exc}")
        return 1
    host, port = server.server_address[:2]
    print(f"cred-proxy listening on http://{host}:{port} "
          f"({len(config.routes)} route(s)); Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


class _EchoHandler(BaseHTTPRequestHandler):
    """Throwaway upstream for the demo: reports the auth header it received."""

    received: list = []

    def log_message(self, format, *args):
        pass

    def _echo(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        auth = self.headers.get("Authorization")
        type(self).received.append(
            {"method": self.command, "path": self.path, "auth": auth})
        payload = json.dumps({"you_sent_auth": auth, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _echo
    do_POST = _echo


def _cmd_demo(args) -> int:
    os.environ["CRED_PROXY_DEMO_KEY"] = DEMO_SECRET
    _EchoHandler.received = []
    echo = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=echo.serve_forever, daemon=True).start()

    config = parse_config({
        "credentials": {"demo": {"env": "CRED_PROXY_DEMO_KEY"}},
        "routes": [{
            "name": "demo",
            "upstream": f"http://127.0.0.1:{echo.server_address[1]}",
            "credential": "demo",
        }],
    })
    proxy = serve(config, host="127.0.0.1", port=0)
    proxy_port = proxy.server_address[1]
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    def call(path, auth=None):
        conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
        headers = {"Authorization": auth} if auth else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        return resp.status, body

    failures = 0

    status, body = call("/demo/v1/models", "proxy:demo")
    upstream_auth = _EchoHandler.received[-1]["auth"]
    swapped = upstream_auth == f"Bearer {DEMO_SECRET}"
    redacted = DEMO_SECRET not in body
    print(f"1. agent sent placeholder 'proxy:demo' -> HTTP {status}")
    print(f"   upstream received the real credential: {swapped}")
    print(f"   the secret echoed back was redacted before the agent saw it: "
          f"{redacted}")
    failures += not (status == 200 and swapped and redacted)

    before = len(_EchoHandler.received)
    status, _ = call("/other/thing", "proxy:demo")
    called = len(_EchoHandler.received) != before
    print(f"2. undeclared route /other -> HTTP {status}, upstream called: {called}")
    failures += not (status == 403 and not called)

    status, _ = call("/demo/v1/models", "proxy:someone-else")
    called = len(_EchoHandler.received) != before
    print(f"3. wrong placeholder 'proxy:someone-else' -> HTTP {status}, "
          f"upstream called: {called}")
    failures += not (status == 403 and not called)

    proxy.shutdown()
    echo.shutdown()
    print("demo OK" if failures == 0 else "demo FAILED")
    return 0 if failures == 0 else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cred-proxy",
        description="Local egress proxy that swaps real API credentials in "
                    "at request time, so an agent never sees the secrets it uses.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="validate a config and list its permissions")
    p.add_argument("--config", required=True)
    p.set_defaults(func=_cmd_check)

    p = sub.add_parser("serve", help="run the proxy")
    p.add_argument("--config", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--allow-remote", action="store_true",
                   help="allow binding a non-loopback host (dangerous: this "
                        "process can use real credentials)")
    p.add_argument("--audit-log", default=None,
                   help="append JSONL audit entries to this file")
    p.set_defaults(func=_cmd_serve)

    p = sub.add_parser("demo", help="run a self-contained demonstration")
    p.set_defaults(func=_cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
