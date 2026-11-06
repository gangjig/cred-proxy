import pytest

from cred_proxy.config import Credential
from cred_proxy.secrets import (SecretError, SecretStore, mask, redact_bytes,
                                redact_text)


def store(**creds):
    return SecretStore(creds)


def test_resolve_from_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "s3cret-value")
    s = store(k=Credential(name="k", env="MY_KEY"))
    assert s.resolve("k") == "s3cret-value"


def test_resolve_from_file(tmp_path):
    path = tmp_path / "token"
    path.write_text("file-secret\n")
    s = store(k=Credential(name="k", file=str(path)))
    assert s.resolve("k") == "file-secret"


def test_resolve_missing_env(monkeypatch):
    monkeypatch.delenv("MY_KEY", raising=False)
    s = store(k=Credential(name="k", env="MY_KEY"))
    with pytest.raises(SecretError, match="not set"):
        s.resolve("k")


def test_resolve_empty_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "")
    s = store(k=Credential(name="k", env="MY_KEY"))
    with pytest.raises(SecretError):
        s.resolve("k")


def test_resolve_missing_file(tmp_path):
    s = store(k=Credential(name="k", file=str(tmp_path / "absent")))
    with pytest.raises(SecretError, match="cannot read"):
        s.resolve("k")


def test_resolve_undeclared():
    with pytest.raises(SecretError, match="undeclared"):
        store().resolve("nope")


def test_resolve_all(monkeypatch):
    monkeypatch.setenv("A", "1")
    monkeypatch.setenv("B", "2")
    s = store(a=Credential(name="a", env="A"), b=Credential(name="b", env="B"))
    assert s.resolve_all() == {"a": "1", "b": "2"}


def test_redact_bytes_replaces_every_occurrence():
    data = b"key is abc123 and again abc123"
    assert redact_bytes(data, ["abc123"]) == b"key is ***REDACTED*** and again ***REDACTED***"


def test_redact_ignores_empty_secret():
    assert redact_bytes(b"unchanged", [""]) == b"unchanged"
    assert redact_text("unchanged", [""]) == "unchanged"


def test_redact_text():
    assert redact_text("token abc123 ok", ["abc123"]) == "token ***REDACTED*** ok"


def test_mask():
    assert mask("sk-1234567890") == "sk...90"
    assert mask("abc") == "****"
