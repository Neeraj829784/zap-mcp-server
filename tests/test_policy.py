"""Tests for the target-authorization policy (the security boundary)."""
import importlib

import pytest


def _reload_policy(monkeypatch, **env):
    """Reload config+policy with the given environment for isolation."""
    for key in [
        "ZAP_API_KEY",
        "ZAP_TARGET_ALLOWLIST",
        "ZAP_BLOCK_PRIVATE_TARGETS",
        "ZAP_ALLOW_INSECURE",
    ]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("ZAP_API_KEY", "test-key")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import config
    import policy

    importlib.reload(config)
    importlib.reload(policy)
    return policy


def test_metadata_endpoint_always_blocked(monkeypatch):
    policy = _reload_policy(monkeypatch, ZAP_TARGET_ALLOWLIST="169.254.169.254")
    # Even if explicitly allowlisted, metadata IP must be refused.
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("http://169.254.169.254/latest/meta-data/")


def test_metadata_hostname_blocked(monkeypatch):
    policy = _reload_policy(monkeypatch)
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("http://metadata.google.internal/")


def test_allowlist_permits_matching_host(monkeypatch):
    policy = _reload_policy(monkeypatch, ZAP_TARGET_ALLOWLIST="example.com")
    assert policy.authorize_target("https://example.com/app") == "example.com"
    # Subdomains of an allowlisted apex are allowed.
    assert policy.authorize_target("https://api.example.com/") == "api.example.com"


def test_allowlist_blocks_nonmatching_host(monkeypatch):
    policy = _reload_policy(monkeypatch, ZAP_TARGET_ALLOWLIST="example.com")
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("https://evil.test/")


def test_no_allowlist_allows_arbitrary_public_host(monkeypatch):
    policy = _reload_policy(monkeypatch)
    assert policy.authorize_target("https://public-firing-range.appspot.com") == (
        "public-firing-range.appspot.com"
    )


def test_block_private_targets(monkeypatch):
    policy = _reload_policy(monkeypatch, ZAP_BLOCK_PRIVATE_TARGETS="true")
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("http://127.0.0.1:8080/")
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("http://10.0.0.5/")


def test_private_allowed_when_flag_off(monkeypatch):
    policy = _reload_policy(monkeypatch, ZAP_BLOCK_PRIVATE_TARGETS="false")
    assert policy.authorize_target("http://127.0.0.1:3000/") == "127.0.0.1"


def test_empty_target_rejected(monkeypatch):
    policy = _reload_policy(monkeypatch)
    with pytest.raises(policy.TargetNotAllowedError):
        policy.authorize_target("")
