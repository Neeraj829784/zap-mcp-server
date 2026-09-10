"""Findings, alerts, alert-filter, and retest MCP tools for OWASP ZAP.

These tools cover triage of scan results: reading alerts, summarising them by
risk, adjusting/suppressing false positives via alert filters, and re-testing
specific alerts to confirm whether they are still present.
"""
from typing import Any, Dict, Optional

from zap_client import cap_list, envelope, zap_client

# ZAP numeric risk levels used by several endpoints.
RISK_LEVELS = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}


@envelope
async def zap_get_alerts(
    baseurl: Optional[str] = None,
    risk_id: Optional[int] = None,
    start: int = 0,
    count: int = 100,
) -> Dict[str, Any]:
    """Get security alerts, optionally filtered by base URL and risk.

    Args:
        baseurl: Only return alerts under this URL.
        risk_id: Filter by risk (0=Info, 1=Low, 2=Medium, 3=High).
        start: Pagination offset.
        count: Max alerts to return.
    """
    params = {
        "baseurl": baseurl,
        "riskId": risk_id,
        "start": start,
        "count": count,
    }
    data = await zap_client.get_view("alert", "alerts", params=params)
    capped = cap_list(data.get("alerts", []))
    return {
        "status": "success",
        "alerts": capped["items"],
        "total": capped["total"],
        "truncated": capped["truncated"],
    }


@envelope
async def zap_get_alerts_summary(baseurl: Optional[str] = None) -> Dict[str, Any]:
    """Get a count of alerts grouped by risk level.

    Args:
        baseurl: Optional base URL filter.
    """
    params = {"baseurl": baseurl} if baseurl else None
    data = await zap_client.get_view("alert", "alertsSummary", params=params)
    return {"status": "success", "summary": data.get("alertsSummary", data)}


@envelope
async def zap_get_alert_details(alert_id: str) -> Dict[str, Any]:
    """Get the full evidence, description, and remediation for one alert.

    Args:
        alert_id: The alert ID.
    """
    data = await zap_client.get_view("alert", "alert", params={"id": alert_id})
    return {"status": "success", "alert": data.get("alert", data)}


@envelope
async def zap_get_number_of_alerts(
    baseurl: Optional[str] = None, risk_id: Optional[int] = None
) -> Dict[str, Any]:
    """Get the total count of alerts, optionally filtered.

    Args:
        baseurl: Optional base URL filter.
        risk_id: Optional risk filter (0-3).
    """
    params = {"baseurl": baseurl, "riskId": risk_id}
    data = await zap_client.get_view("alert", "numberOfAlerts", params=params)
    return {"status": "success", "number_of_alerts": int(data.get("numberOfAlerts", 0))}


@envelope
async def zap_delete_all_alerts() -> Dict[str, Any]:
    """Delete all alerts from the current session."""
    data = await zap_client.execute_action("alert", "deleteAllAlerts")
    return {"status": "success", "result": data}


# --- Alert filters (false-positive / risk management) -----------------------


@envelope
async def zap_add_alert_filter(
    context_id: str,
    rule_id: str,
    new_level: str,
    url: Optional[str] = None,
    url_is_regex: Optional[bool] = None,
    parameter: Optional[str] = None,
    enabled: bool = True,
) -> Dict[str, Any]:
    """Add an alert filter to re-classify or suppress a scan rule's alerts.

    Useful for marking confirmed false positives without losing the finding.

    Args:
        context_id: The context the filter applies to.
        rule_id: The scan rule (plugin) ID to filter.
        new_level: Target risk as a string: '-1' (False Positive), '0'
            (Informational), '1' (Low), '2' (Medium), '3' (High).
        url: Optional URL the filter applies to (can be a regex).
        url_is_regex: Whether ``url`` is a regex.
        parameter: Optional parameter name the filter applies to.
        enabled: Whether the filter is enabled.
    """
    params = {
        "contextId": context_id,
        "ruleId": rule_id,
        "newLevel": new_level,
        "url": url,
        "urlIsRegex": url_is_regex,
        "parameter": parameter,
        "enabled": enabled,
    }
    data = await zap_client.execute_action(
        "alertFilter", "addAlertFilter", params=params
    )
    return {"status": "success", "result": data}


@envelope
async def zap_list_alert_filters(context_id: str) -> Dict[str, Any]:
    """List the alert filters configured for a context.

    Args:
        context_id: The context ID.
    """
    data = await zap_client.get_view(
        "alertFilter", "alertFilterList", params={"contextId": context_id}
    )
    return {"status": "success", "alert_filters": data.get("alertFilterList", data)}


@envelope
async def zap_apply_alert_filters(context_id: str) -> Dict[str, Any]:
    """Apply a context's alert filters to existing alerts.

    Args:
        context_id: The context ID whose filters to apply.
    """
    data = await zap_client.execute_action("alertFilter", "applyContext")
    return {"status": "success", "context_id": context_id, "result": data}


# --- Retest -----------------------------------------------------------------


@envelope
async def zap_retest_alerts(alert_ids: str) -> Dict[str, Any]:
    """Re-test one or more alerts to confirm whether they are still present.

    Requires the Retest add-on. Useful for verifying remediation.

    Args:
        alert_ids: Comma-separated alert IDs to retest.
    """
    data = await zap_client.execute_action(
        "retest", "retest", params={"alertIds": alert_ids}
    )
    return {"status": "success", "result": data}
