import json

import pytest

from cred_proxy.config import ConfigError, load_config, parse_config

VALID = {
    "credentials": {"openai": {"env": "OPENAI_API_KEY"}},
    "routes": [{"name": "openai", "upstream": "https://api.openai.com",
                "credential": "openai"}],
}


def test_valid_config_defaults():
    config = parse_config(VALID)
    route = config.routes["openai"]
    assert route.header == "Authorization"
    assert route.template == "Bearer {secret}"
    assert route.placeholder == "proxy:openai"
    assert config.credentials["openai"].env == "OPENAI_API_KEY"


def test_custom_header_and_template():
    data = json.loads(json.dumps(VALID))
    data["routes"][0]["header"] = "X-Api-Key"
    data["routes"][0]["template"] = "{secret}"
    route = parse_config(data).routes["openai"]
    assert route.header == "X-Api-Key"
    assert route.template == "{secret}"


def test_route_for_path():
    config = parse_config(VALID)
    route, rest = config.route_for_path("/openai/v1/models")
    assert route.name == "openai"
    assert rest == "/v1/models"
    route, rest = config.route_for_path("/openai")
    assert rest == "/"
    assert config.route_for_path("/nope/x") is None
    assert config.route_for_path("/") is None


def test_duplicate_route_names_rejected():
    data = json.loads(json.dumps(VALID))
    data["routes"].append(dict(data["routes"][0]))
    with pytest.raises(ConfigError, match="duplicate"):
        parse_config(data)


def test_undeclared_credential_rejected():
    data = json.loads(json.dumps(VALID))
    data["routes"][0]["credential"] = "missing"
    with pytest.raises(ConfigError, match="undeclared credential"):
        parse_config(data)


def test_credential_needs_exactly_one_source():
    for spec in ({"env": "A", "file": "b"}, {}):
        data = {"credentials": {"c": spec},
                "routes": [{"name": "r", "upstream": "https://x.example",
                            "credential": "c"}]}
        with pytest.raises(ConfigError, match="exactly one"):
            parse_config(data)


def test_template_must_contain_secret():
    data = json.loads(json.dumps(VALID))
    data["routes"][0]["template"] = "Bearer token"
    with pytest.raises(ConfigError, match="template"):
        parse_config(data)


def test_upstream_must_be_http_url():
    for bad in ("api.openai.com", "ftp://example.com", "https://"):
        data = json.loads(json.dumps(VALID))
        data["routes"][0]["upstream"] = bad
        with pytest.raises(ConfigError, match="upstream"):
            parse_config(data)


def test_no_routes_rejected():
    with pytest.raises(ConfigError, match="no routes"):
        parse_config({"credentials": {}, "routes": []})


def test_load_config_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(VALID))
    assert "openai" in load_config(path).routes


def test_load_config_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "absent.json")


def test_load_config_invalid_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(path)
