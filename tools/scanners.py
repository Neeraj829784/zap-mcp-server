"""Active and passive scanner MCP tools for OWASP ZAP.

Active scanning is attack traffic. Every entry point that launches or resumes an
active scan is gated by :func:`policy.authorize_target` (for URL-based scans) so
the model cannot direct an attack at unauthorised or internal infrastructure.
Passive-scan tools observe existing traffic and are not gated.
"""
from typing import Any, Dict, Optional

from policy import TargetNotAllowedError, authorize_target
from zap_client import ZAPClientError, envelope, zap_client


def _target_error(exc: TargetNotAllowedError) -> Dict[str, Any]:
    return {
        "status": "error",
        "code": "target_not_allowed",
        "message": str(exc),
        "retryable": False,
    }


# --- Active scanner ---------------------------------------------------------


@envelope
async def zap_active_scan(
    url: str,
    recurse: bool = True,
    in_scope_only: bool = False,
    scan_policy_name: Optional[str] = None,
    method: Optional[str] = None,
    post_data: Optional[str] = None,
    context_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Start an active vulnerability scan against a target URL.

    The target is checked against the server-side authorization policy before
    any attack traffic is generated.

    Args:
        url: The target URL to attack.
        recurse: Scan URLs beneath the target.
        in_scope_only: Constrain to in-scope URLs (ignored if a context is set).
        scan_policy_name: Optional named scan policy (defaults to ZAP's default).
        method: Optional HTTP method to target a specific request.
        post_data: Optional POST body to target a specific request.
        context_id: Optional context to constrain the scan.
    """
    try:
        authorize_target(url)
    except TargetNotAllowedError as exc:
        return _target_error(exc)

    params = {
        "url": url,
        "recurse": recurse,
        "inScopeOnly": in_scope_only,
        "scanPolicyName": scan_policy_name,
        "method": method,
        "postData": post_data,
        "contextId": context_id,
    }
    data = await zap_client.execute_action("ascan", "scan", params=params)
    return {"status": "success", "scan_id": data.get("scan")}


@envelope
async def zap_active_scan_as_user(
    url: str,
    context_id: str,
    user_id: str,
    recurse: bool = True,
    scan_policy_name: Optional[str] = None,
    method: Optional[str] = None,
    post_data: Optional[str] = None,
) -> Dict[str, Any]:
    """Start an active scan authenticated as a specific user.

    Requires the context to have an authentication method and the user to have
    credentials configured (see the auth/users tools).

    Args:
        url: The target URL to attack.
        context_id: The context ID whose auth config to use.
        user_id: The user ID to authenticate as.
        recurse: Scan URLs beneath the target.
        scan_policy_name: Optional named scan policy.
        method: Optional HTTP method to target a specific request.
        post_data: Optional POST body to target a specific request.
    """
    try:
        authorize_target(url)
    except TargetNotAllowedError as exc:
        return _target_error(exc)

    params = {
        "url": url,
        "contextId": context_id,
        "userId": user_id,
        "recurse": recurse,
        "scanPolicyName": scan_policy_name,
        "method": method,
        "postData": post_data,
    }
    data = await zap_client.execute_action("ascan", "scanAsUser", params=params)
    return {"status": "success", "scan_id": data.get("scan")}


@envelope
async def zap_active_scan_status(scan_id: str) -> Dict[str, Any]:
    """Get the completion percentage of an active scan.

    Args:
        scan_id: The scan ID returned when the scan was started.
    """
    data = await zap_client.get_view("ascan", "status", params={"scanId": scan_id})
    progress = int(data.get("status", 0))
    return {
        "status": "success",
        "scan_id": scan_id,
        "progress_percent": progress,
        "is_complete": progress >= 100,
    }


@envelope
async def zap_active_scan_progress(scan_id: str) -> Dict[str, Any]:
    """Get detailed per-rule progress of an active scan.

    Args:
        scan_id: The scan ID.
    """
    data = await zap_client.get_view(
        "ascan", "scanProgress", params={"scanId": scan_id}
    )
    return {"status": "success", "scan_id": scan_id, "rules": data.get("scanProgress", [])}


@envelope
async def zap_active_scan_stop(scan_id: str) -> Dict[str, Any]:
    """Stop a running active scan.

    Args:
        scan_id: The scan ID to stop.
    """
    data = await zap_client.execute_action("ascan", "stop", params={"scanId": scan_id})
    return {"status": "success", "scan_id": scan_id, "result": data}


@envelope
async def zap_active_scan_pause(scan_id: str) -> Dict[str, Any]:
    """Pause a running active scan.

    Args:
        scan_id: The scan ID to pause.
    """
    data = await zap_client.execute_action("ascan", "pause", params={"scanId": scan_id})
    return {"status": "success", "scan_id": scan_id, "result": data}


@envelope
async def zap_active_scan_resume(scan_id: str) -> Dict[str, Any]:
    """Resume a paused active scan.

    Args:
        scan_id: The scan ID to resume.
    """
    data = await zap_client.execute_action("ascan", "resume", params={"scanId": scan_id})
    return {"status": "success", "scan_id": scan_id, "result": data}


@envelope
async def zap_list_scan_policies() -> Dict[str, Any]:
    """List the available active-scan policy names."""
    data = await zap_client.get_view("ascan", "scanPolicyNames")
    return {"status": "success", "scan_policies": data.get("scanPolicyNames", data)}


# --- Passive scanner --------------------------------------------------------


@envelope
async def zap_passive_scan_status() -> Dict[str, Any]:
    """Get the number of records left in the passive-scan queue."""
    data = await zap_client.get_view("pscan", "recordsToScan")
    records = int(data.get("recordsToScan", 0))
    return {
        "status": "success",
        "records_to_scan": records,
        "is_complete": records == 0,
    }


@envelope
async def zap_passive_scan_set_enabled(enabled: bool) -> Dict[str, Any]:
    """Enable or disable passive scanning.

    Args:
        enabled: True to enable, False to disable.
    """
    data = await zap_client.execute_action(
        "pscan", "setEnabled", params={"enabled": enabled}
    )
    return {"status": "success", "enabled": enabled, "result": data}


@envelope
async def zap_passive_scan_clear_queue() -> Dict[str, Any]:
    """Clear all pending messages from the passive-scan queue."""
    data = await zap_client.execute_action("pscan", "clearQueue")
    return {"status": "success", "result": data}
