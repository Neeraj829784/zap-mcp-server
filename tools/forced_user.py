"""Forced-user mode MCP tools for OWASP ZAP.

Covers Step 6 of ZAP's authenticated-scanning workflow. When forced-user mode is
enabled for a context, ZAP re-sends the authentication request whenever it
detects (via the logged-in/out indicators) that the user is no longer logged in.
This keeps sessions alive during long crawls and scans.

These configure ZAP state only and do not attack the target.
"""
from typing import Any, Dict

from zap_client import envelope, zap_client


@envelope
async def zap_set_forced_user(context_id: str, user_id: str) -> Dict[str, Any]:
    """Set which user is used when forced-user mode is enabled for a context.

    Args:
        context_id: The numeric context ID.
        user_id: The user ID to force.
    """
    params = {"contextId": context_id, "userId": user_id}
    data = await zap_client.execute_action("forcedUser", "setForcedUser", params=params)
    return {
        "status": "success",
        "context_id": context_id,
        "user_id": user_id,
        "result": data,
    }


@envelope
async def zap_set_forced_user_mode(enabled: bool = True) -> Dict[str, Any]:
    """Enable or disable forced-user mode globally.

    Note: this is a global toggle in ZAP, not per-context. It is ignored for
    scans that already have a user explicitly set (e.g. ``scan_as_user``).

    Args:
        enabled: True to enable forced-user mode, False to disable.
    """
    params = {"boolean": enabled}
    data = await zap_client.execute_action(
        "forcedUser", "setForcedUserModeEnabled", params=params
    )
    return {"status": "success", "enabled": enabled, "result": data}


@envelope
async def zap_get_forced_user(context_id: str) -> Dict[str, Any]:
    """Get the user ID currently set as forced user for a context.

    Args:
        context_id: The numeric context ID.
    """
    data = await zap_client.get_view(
        "forcedUser", "getForcedUser", params={"contextId": context_id}
    )
    return {"status": "success", "context_id": context_id, "forced_user": data}


@envelope
async def zap_is_forced_user_mode_enabled() -> Dict[str, Any]:
    """Report whether forced-user mode is currently enabled."""
    data = await zap_client.get_view("forcedUser", "isForcedUserModeEnabled")
    return {"status": "success", "enabled": data.get("isForcedUserModeEnabled", data)}
