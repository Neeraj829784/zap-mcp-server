"""Tests for the result envelope and typed error handling."""
import importlib

import pytest


@pytest.fixture
def zc(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "test-key")
    import config
    import zap_client

    importlib.reload(config)
    importlib.reload(zap_client)
    return zap_client


async def test_envelope_wraps_plain_result(zc):
    @zc.envelope
    async def tool():
        return {"data": 123}

    result = await tool()
    assert result == {"status": "success", "result": {"data": 123}}


async def test_envelope_passthrough_status_dict(zc):
    @zc.envelope
    async def tool():
        return {"status": "success", "version": "2.17.0"}

    result = await tool()
    assert result["status"] == "success"
    assert result["version"] == "2.17.0"


async def test_envelope_maps_zap_error_to_structured(zc):
    @zc.envelope
    async def tool():
        raise zc.ZAPTimeoutError("timed out")

    result = await tool()
    assert result["status"] == "error"
    assert result["code"] == "zap_timeout"
    assert result["retryable"] is True
    assert "timed out" in result["message"]


async def test_envelope_catches_unexpected_exception(zc):
    @zc.envelope
    async def tool():
        raise ValueError("boom")

    result = await tool()
    assert result["status"] == "error"
    assert result["code"] == "internal_error"
    assert result["retryable"] is False


async def test_api_error_has_code(zc):
    err = zc.ZAPAPIError("bad", code="does_not_exist", http_status=400)
    assert err.code == "does_not_exist"
    assert err.http_status == 400
    assert err.retryable is False
