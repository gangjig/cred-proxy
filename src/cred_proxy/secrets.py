"""Secret resolution and redaction.

The proxy resolves each declared credential from an environment variable or
a file, at startup (fail fast) and again per request. Secret values are
never written to the audit log, and any secret that comes back inside an
upstream response is redacted before the response reaches the agent.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .config import Credential

REDACTED = b"***REDACTED***"


class SecretError(RuntimeError):
    """Raised when a declared credential cannot be resolved."""


class SecretStore:
    def __init__(self, credentials: dict[str, Credential]):
        self._credentials = dict(credentials)

    def resolve(self, name: str) -> str:
        cred = self._credentials.get(name)
        if cred is None:
            raise SecretError(f"undeclared credential {name!r}")
        if cred.env is not None:
            value = os.environ.get(cred.env)
            if not value:
                raise SecretError(
                    f"credential {name!r}: environment variable "
                    f"{cred.env} is not set or is empty"
                )
            return value
        path = Path(cred.file).expanduser()
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecretError(
                f"credential {name!r}: cannot read {path}: {exc}"
            ) from exc
        if not value:
            raise SecretError(f"credential {name!r}: file {path} is empty")
        return value

    def resolve_all(self) -> dict[str, str]:
        return {name: self.resolve(name) for name in self._credentials}


def redact_bytes(data: bytes, secrets: Iterable[str]) -> bytes:
    out = data
    for secret in secrets:
        if secret:
            out = out.replace(secret.encode("utf-8"), REDACTED)
    return out


def redact_text(text: str, secrets: Iterable[str]) -> str:
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, REDACTED.decode("ascii"))
    return out


def mask(secret: str) -> str:
    """Show just enough of a secret for a human to recognise it."""
    if len(secret) <= 4:
        return "****"
    return f"{secret[:2]}...{secret[-2:]}"
