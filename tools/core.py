"""Core and session management MCP tools for OWASP ZAP."""
from typing import Any, Dict

from policy import TargetNotAllowedError, authorize_target
from zap_client import cap_list, envelope, zap_client


@envelope
async def zap_get_version() -> Dict[str, Any]:
    """Get the running ZAP version (also serves as a health check)."""
    data = await zap_client.get_view("core", "version")
    return {"status": "success", "version": data.get("version")}


@envelope
async def zap_access_url(url: str, follow_redirects: bool = True) -> Dict[str, Any]:
    """Access a URL through ZAP to seed the site tree and trigger passive scan.

    This sends a request to the target, so it is gated by the target policy.

    Args:
        url: The full target URL (e.g. https://example.com).
        follow_redirects: Whether ZAP should follow redirects.
    """
    try:
        authorize_target(url)
    except TargetNotAllowedError as exc:
        return {
            "status": "error",
            "code": "target_not_allowed",
            "message": str(exc),
            "retryable": False,
        }
    params = {"url": url, "followRedirects": follow_redirects}
    data = await zap_client.execute_action("core", "accessUrl", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_get_sites() -> Dict[str, Any]:
    """List the base sites recorded in the ZAP site tree."""
    data = await zap_client.get_view("core", "sites")
    capped = cap_list(data.get("sites", []))
    return {
        "status": "success",
        "sites": capped["items"],
        "total": capped["total"],
        "truncated": capped["truncated"],
    }


@envelope
async def zap_get_urls() -> Dict[str, Any]:
    """List all URLs discovered across the site tree."""
    data = await zap_client.get_view("core", "urls")
    capped = cap_list(data.get("urls", []))
    return {
        "status": "success",
        "urls": capped["items"],
        "total": capped["total"],
        "truncated": capped["truncated"],
    }


@envelope
async def zap_new_session(name: str = "", overwrite: bool = True) -> Dict[str, Any]:
    """Create a new ZAP session, resetting scan state and the site tree.

    Args:
        name: Optional session name/path.
        overwrite: Overwrite an existing session with the same name.
    """
    params = {"name": name, "overwrite": overwrite}
    data = await zap_client.execute_action("core", "newSession", params=params)
    return {"status": "success", "result": data}
