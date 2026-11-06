import json

from cred_proxy.cli import main

CONFIG = {
    "credentials": {"openai": {"env": "OPENAI_API_KEY"}},
    "routes": [{"name": "openai", "upstream": "https://api.openai.com",
                "credential": "openai"}],
}


def write_config(tmp_path, data=CONFIG):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_check_ok(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-example-123456")
    assert main(["check", "--config", write_config(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "credential openai: resolvable" in out
    assert "sk-example-123456" not in out  # masked, never printed in full
    assert "route /openai -> https://api.openai.com" in out


def test_check_missing_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert main(["check", "--config", write_config(tmp_path)]) == 1


def test_check_bad_config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{oops")
    assert main(["check", "--config", str(path)]) == 1


def test_check_missing_file(tmp_path):
    assert main(["check", "--config", str(tmp_path / "absent.json")]) == 1


def test_demo(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "upstream received the real credential: True" in out
    assert "demo OK" in out
