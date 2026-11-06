"""Configuration loading and validation for cred-proxy.

A config declares credentials (where each real secret lives) and routes
(which upstream a credential may be used for, and how it is presented).
Anything not declared here is refused by the proxy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    """Raised when a cred-proxy configuration is invalid."""


@dataclass(frozen=True)
class Credential:
    name: str
    env: str | None = None
    file: str | None = None


@dataclass(frozen=True)
class Route:
    name: str
    upstream: str
    credential: str
    header: str = "Authorization"
    template: str = "Bearer {secret}"

    @property
    def placeholder(self) -> str:
        """The placeholder value an agent sends instead of the real secret."""
        return f"proxy:{self.credential}"


@dataclass(frozen=True)
class Config:
    credentials: dict[str, Credential]
    routes: dict[str, Route]

    def route_for_path(self, path: str) -> tuple[Route, str] | None:
        """Match ``/<route-name>/rest`` -> ``(route, rest)``; None if undeclared."""
        parts = path.split("/", 2)
        if len(parts) < 2 or not parts[1]:
            return None
        route = self.routes.get(parts[1])
        if route is None:
            return None
        rest = "/" + parts[2] if len(parts) == 3 else "/"
        return route, rest


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file {p} is not valid JSON: {exc}") from exc
    return parse_config(data)


def parse_config(data) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")

    credentials: dict[str, Credential] = {}
    for name, spec in (data.get("credentials") or {}).items():
        if not isinstance(spec, dict):
            raise ConfigError(f"credential {name!r} must be an object")
        env = spec.get("env")
        file = spec.get("file")
        if bool(env) == bool(file):
            raise ConfigError(
                f"credential {name!r} must set exactly one of 'env' or 'file'"
            )
        credentials[name] = Credential(name=name, env=env, file=file)

    routes: dict[str, Route] = {}
    for spec in data.get("routes") or []:
        if not isinstance(spec, dict):
            raise ConfigError("each route must be an object")
        name = spec.get("name")
        upstream = spec.get("upstream")
        credential = spec.get("credential")
        if not name or not upstream or not credential:
            raise ConfigError("each route needs 'name', 'upstream' and 'credential'")
        if name in routes:
            raise ConfigError(f"duplicate route name {name!r}")
        if credential not in credentials:
            raise ConfigError(
                f"route {name!r} uses undeclared credential {credential!r}"
            )
        parsed = urlparse(upstream)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ConfigError(
                f"route {name!r} upstream must be an http(s) URL, got {upstream!r}"
            )
        template = spec.get("template", "Bearer {secret}")
        if "{secret}" not in template:
            raise ConfigError(f"route {name!r} template must contain '{{secret}}'")
        routes[name] = Route(
            name=name,
            upstream=upstream.rstrip("/"),
            credential=credential,
            header=spec.get("header", "Authorization"),
            template=template,
        )

    if not routes:
        raise ConfigError("config declares no routes")
    return Config(credentials=credentials, routes=routes)
