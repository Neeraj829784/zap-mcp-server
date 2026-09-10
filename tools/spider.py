"""Discovery / crawling MCP tools for OWASP ZAP.

Spidering sends requests to the target, so URL-based crawl entry points are
gated by the target-authorization policy. Status/results/stop calls are not.
"""
from typing import Any, Dict, Optional

from policy import TargetNotAllowedError, authorize_target
from zap_client import envelope, zap_client


def _target_error(exc: TargetNotAllowedError) -> Dict[str, Any]:
    return {
        "status": "error",
        "code": "target_not_allowed",
        "message": str(exc),
        "retryable": False,
    }


# --- Traditional spider -----------------------------------------------------


@envelope
async def zap_spider_scan(
    url: str,
    max_children: Optional[int] = None,
    recurse: bool = True,
    context_name: Optional[str] = None,
    subtree_only: bool = False,
) -> Dict[str, Any]:
    """Start a traditional spider crawl to discover endpoints.

    Args:
        url: Target URL to crawl.
        max_children: Max child nodes to crawl per node (0/None = unlimited).
        recurse: Crawl recursively.
        context_name: Optional context to constrain the crawl.
        subtree_only: Restrict crawling to the URL's subtree.
    """
    try:
        authorize_target(url)
    except TargetNotAllowedError as exc:
        return _target_error(exc)

    params = {
        "url": url,
        "maxChildren": max_children,
        "recurse": recurse,
        "contextName": context_name,
        "subtreeOnly": subtree_only,
    }
    data = await zap_client.execute_action("spider", "scan", params=params)
    return {"status": "success", "scan_id": data.get("scan")}


@envelope
async def zap_spider_scan_as_user(
    context_id: str,
    user_id: str,
    url: Optional[str] = None,
    max_children: Optional[int] = None,
    recurse: bool = True,
    subtree_only: bool = False,
) -> Dict[str, Any]:
    """Start a traditional spider crawl authenticated as a specific user.

    Args:
        context_id: The context ID whose auth config to use.
        user_id: The user ID to authenticate as.
        url: Optional starting URL (defaults to the context's scope).
        max_children: Max child nodes per node.
        recurse: Crawl recursively.
        subtree_only: Restrict crawling to the URL's subtree.
    """
    if url:
        try:
            authorize_target(url)
        except TargetNotAllowedError as exc:
            return _target_error(exc)

    params = {
        "contextId": context_id,
        "userId": user_id,
        "url": url,
        "maxChildren": max_children,
        "recurse": recurse,
        "subtreeOnly": subtree_only,
    }
    data = await zap_client.execute_action("spider", "scanAsUser", params=params)
    return {"status": "success", "scan_id": data.get("scan")}


@envelope
async def zap_spider_status(scan_id: str) -> Dict[str, Any]:
    """Get the completion percentage of a spider scan.

    Args:
        scan_id: The scan ID returned when the crawl started.
    """
    data = await zap_client.get_view("spider", "status", params={"scanId": scan_id})
    progress = int(data.get("status", 0))
    return {
        "status": "success",
        "scan_id": scan_id,
        "progress_percent": progress,
        "is_complete": progress >= 100,
    }


@envelope
async def zap_spider_results(scan_id: str) -> Dict[str, Any]:
    """Get the URLs discovered by a spider scan.

    Args:
        scan_id: The scan ID.
    """
    data = await zap_client.get_view("spider", "results", params={"scanId": scan_id})
    return {"status": "success", "scan_id": scan_id, "urls": data.get("results", [])}


@envelope
async def zap_spider_stop(scan_id: str) -> Dict[str, Any]:
    """Stop a running spider scan.

    Args:
        scan_id: The scan ID to stop.
    """
    data = await zap_client.execute_action("spider", "stop", params={"scanId": scan_id})
    return {"status": "success", "scan_id": scan_id, "result": data}


# --- AJAX spider (JS/SPA crawler) -------------------------------------------


@envelope
async def zap_ajax_spider_scan(
    url: str,
    in_scope: bool = False,
    context_name: Optional[str] = None,
    subtree_only: bool = False,
) -> Dict[str, Any]:
    """Launch the headless-browser AJAX spider for JS-heavy / SPA apps.

    Args:
        url: Target URL to crawl.
        in_scope: Restrict to in-scope resources (ignored if context is set).
        context_name: Optional context to constrain the crawl.
        subtree_only: Restrict crawling to the URL's subtree.
    """
    try:
        authorize_target(url)
    except TargetNotAllowedError as exc:
        return _target_error(exc)

    params = {
        "url": url,
        "inScope": in_scope,
        "contextName": context_name,
        "subtreeOnly": subtree_only,
    }
    data = await zap_client.execute_action("ajaxSpider", "scan", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_ajax_spider_scan_as_user(
    context_name: str,
    user_name: str,
    url: Optional[str] = None,
    subtree_only: bool = False,
) -> Dict[str, Any]:
    """Launch the AJAX spider authenticated as a specific user.

    Note: this endpoint identifies the user by *name*, not ID, and the user must
    already be defined on the named context.

    Args:
        context_name: The context name whose auth config to use.
        user_name: The user name to authenticate as.
        url: Optional starting URL.
        subtree_only: Restrict crawling to the URL's subtree.
    """
    if url:
        try:
            authorize_target(url)
        except TargetNotAllowedError as exc:
            return _target_error(exc)

    params = {
        "contextName": context_name,
        "userName": user_name,
        "url": url,
        "subtreeOnly": subtree_only,
    }
    data = await zap_client.execute_action("ajaxSpider", "scanAsUser", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_ajax_spider_status() -> Dict[str, Any]:
    """Get the AJAX spider state ('running' or 'stopped')."""
    data = await zap_client.get_view("ajaxSpider", "status")
    state = data.get("status", "unknown")
    return {"status": "success", "ajax_spider_status": state, "is_running": state == "running"}


@envelope
async def zap_ajax_spider_results(start: int = 0, count: int = 100) -> Dict[str, Any]:
    """Get URLs/resources found by the AJAX spider.

    Args:
        start: Offset into the result set.
        count: Number of results to return.
    """
    params = {"start": start, "count": count}
    data = await zap_client.get_view("ajaxSpider", "fullResults", params=params)
    return {"status": "success", "results": data}


@envelope
async def zap_ajax_spider_stop() -> Dict[str, Any]:
    """Stop a running AJAX spider crawl."""
    data = await zap_client.execute_action("ajaxSpider", "stop")
    return {"status": "success", "result": data}
