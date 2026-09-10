"""Tests for tool behaviour using a mocked ZAP client.

These verify the two things most likely to cause silent, dangerous failures for
a bug-bounty user:
  1. The auth-methods fix reads the correct JSON key.
  2. Attack-capable tools refuse disallowed targets *before* calling ZAP.
"""
import importlib

import pytest


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "test-key")
    monkeypatch.delenv("ZAP_TARGET_ALLOWLIST", raising=False)
    monkeypatch.setenv("ZAP_BLOCK_PRIVATE_TARGETS", "false")
    import config

    importlib.reload(config)
    return config


class FakeClient:
    """Records calls and returns canned responses."""

    def __init__(self):
        self.actions = []
        self.views = []
        self.view_response = {}
        self.action_response = {}

    async def get_view(self, component, view, params=None):
        self.views.append((component, view, params))
        return self.view_response

    async def execute_action(self, component, action, params=None):
        self.actions.append((component, action, params))
        return self.action_response


async def test_get_auth_methods_reads_supported_methods(env, monkeypatch):
    import tools.auth as auth

    importlib.reload(auth)
    fake = FakeClient()
    fake.view_response = {"supportedMethods": ["formBasedAuthentication"]}
    monkeypatch.setattr(auth, "zap_client", fake)

    result = await auth.zap_get_auth_methods()
    assert result["status"] == "success"
    assert result["methods"] == ["formBasedAuthentication"]


async def test_active_scan_blocks_metadata_target(env, monkeypatch):
    import policy
    import tools.scanners as scanners

    importlib.reload(policy)
    importlib.reload(scanners)
    fake = FakeClient()
    monkeypatch.setattr(scanners, "zap_client", fake)

    result = await scanners.zap_active_scan("http://169.254.169.254/")
    assert result["status"] == "error"
    assert result["code"] == "target_not_allowed"
    # Crucially, ZAP was never called.
    assert fake.actions == []


async def test_active_scan_allows_and_calls_zap(env, monkeypatch):
    import policy
    import tools.scanners as scanners

    importlib.reload(policy)
    importlib.reload(scanners)
    fake = FakeClient()
    fake.action_response = {"scan": "42"}
    monkeypatch.setattr(scanners, "zap_client", fake)

    result = await scanners.zap_active_scan("https://public-firing-range.appspot.com")
    assert result["status"] == "success"
    assert result["scan_id"] == "42"
    assert fake.actions and fake.actions[0][:2] == ("ascan", "scan")


async def test_spider_blocks_disallowed_when_allowlist_set(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "test-key")
    monkeypatch.setenv("ZAP_TARGET_ALLOWLIST", "example.com")
    import config
    import policy
    import tools.spider as spider

    importlib.reload(config)
    importlib.reload(policy)
    importlib.reload(spider)
    fake = FakeClient()
    monkeypatch.setattr(spider, "zap_client", fake)

    result = await spider.zap_spider_scan("https://not-in-scope.test/")
    assert result["status"] == "error"
    assert result["code"] == "target_not_allowed"
    assert fake.actions == []


async def test_report_filename_is_sanitized(env, monkeypatch):
    import tools.reports as reports

    importlib.reload(reports)
    fake = FakeClient()
    fake.action_response = {"generate": "/zap/wrk/report.html"}
    monkeypatch.setattr(reports, "zap_client", fake)

    result = await reports.zap_generate_report(
        title="t", report_file_name="../../etc/passwd"
    )
    assert result["status"] == "success"
    # Path traversal stripped to a basename.
    assert result["report_file_name"] == "passwd"
    sent_params = fake.actions[0][2]
    assert sent_params["reportFileName"] == "passwd"
