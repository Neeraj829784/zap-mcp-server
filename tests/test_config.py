"""Tests for configuration validation (fail-closed behaviour)."""
import importlib

import pytest


def _reload_config(monkeypatch, **env):
    # Prevent a local .env (present in real deployments) from populating vars so
    # these tests deterministically validate the fail-closed logic.
    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)
    for key in [
        "ZAP_API_KEY",
        "ZAP_ALLOW_INSECURE",
        "ZAP_BASE_URL",
        "REQUEST_TIMEOUT",
        "CONNECT_TIMEOUT",
        "MCP_PORT",
    ]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import config

    importlib.reload(config)
    return config


def test_missing_api_key_fails_closed(monkeypatch):
    config = None
    with pytest.raises(Exception) as excinfo:
        _reload_config(monkeypatch)  # no ZAP_API_KEY, no insecure flag
    assert "ZAP_API_KEY" in str(excinfo.value)


def test_allow_insecure_permits_missing_key(monkeypatch):
    config = _reload_config(monkeypatch, ZAP_ALLOW_INSECURE="true")
    assert config.settings.zap_api_key == ""
    assert config.settings.allow_insecure is True


def test_invalid_base_url_rejected(monkeypatch):
    with pytest.raises(Exception):
        _reload_config(monkeypatch, ZAP_API_KEY="k", ZAP_BASE_URL="ftp://nope")


def test_out_of_range_port_rejected(monkeypatch):
    with pytest.raises(Exception):
        _reload_config(monkeypatch, ZAP_API_KEY="k", MCP_PORT="99999")


def test_connect_timeout_cannot_exceed_request_timeout(monkeypatch):
    with pytest.raises(Exception):
        _reload_config(
            monkeypatch,
            ZAP_API_KEY="k",
            REQUEST_TIMEOUT="5",
            CONNECT_TIMEOUT="10",
        )


def test_redacted_summary_never_contains_key(monkeypatch):
    config = _reload_config(monkeypatch, ZAP_API_KEY="super-secret-value")
    summary = config.settings.redacted_summary
    assert "super-secret-value" not in str(summary)
    assert summary["zap_api_key_set"] is True
