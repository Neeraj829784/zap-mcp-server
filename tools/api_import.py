"""Import and automation MCP tools for OWASP ZAP.

Covers seeding ZAP with API definitions (OpenAPI, GraphQL, Postman), traffic
(HAR), and running Automation Framework plans for repeatable scans. Import
sources are files/URLs consumed by ZAP; they are not gated by the target policy
because they populate the site tree rather than attack a host (the subsequent
active scan is what enforces target authorization).
"""
from typing import Any, Dict, Optional

from zap_client import envelope, zap_client


@envelope
async def zap_import_openapi_url(
    url: str,
    host_override: Optional[str] = None,
    context_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Import an OpenAPI/Swagger definition from a URL.

    Args:
        url: Direct URL to the OpenAPI/Swagger spec.
        host_override: Optional target host to override the spec's server URL.
        context_id: Optional context to associate imported URLs with.
    """
    params = {"url": url, "hostOverride": host_override, "contextId": context_id}
    data = await zap_client.execute_action("openapi", "importUrl", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_import_openapi_file(
    file_path: str,
    target_url: Optional[str] = None,
    context_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Import an OpenAPI/Swagger definition from a local file.

    Args:
        file_path: Absolute path to the spec file, resolved on the ZAP
            container's filesystem. Place the file in the shared work directory
            (``/zap/wrk``, mounted in both containers) so ZAP can read it.
        target_url: Optional target URL to override the spec's server URL.
        context_id: Optional context to associate imported URLs with.
    """
    params = {"file": file_path, "target": target_url, "contextId": context_id}
    data = await zap_client.execute_action("openapi", "importFile", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_import_graphql_url(
    end_point: str, context_id: Optional[str] = None
) -> Dict[str, Any]:
    """Import and introspect a GraphQL endpoint from a URL.

    Args:
        end_point: The GraphQL endpoint URL.
        context_id: Optional context to associate imported URLs with.
    """
    params = {"endurl": end_point, "contextId": context_id}
    data = await zap_client.execute_action("graphql", "importUrl", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_import_har(file_path: str) -> Dict[str, Any]:
    """Import HTTP traffic from a HAR file to seed the site tree.

    Args:
        file_path: Absolute path to the HAR file, resolved on the ZAP
            container's filesystem. Place the file in the shared work directory
            (``/zap/wrk``, mounted in both containers) so ZAP can read it.
    """
    data = await zap_client.execute_action(
        "exim", "importHar", params={"filePath": file_path}
    )
    return {"status": "success", "result": data}


@envelope
async def zap_import_urls(file_path: str) -> Dict[str, Any]:
    """Import a list of URLs (one per line) from a file.

    Args:
        file_path: Absolute path to the URL list file, resolved on the ZAP
            container's filesystem. Place the file in the shared work directory
            (``/zap/wrk``, mounted in both containers) so ZAP can read it.
    """
    data = await zap_client.execute_action(
        "exim", "importUrls", params={"filePath": file_path}
    )
    return {"status": "success", "result": data}


@envelope
async def zap_run_automation_plan(file_path: str) -> Dict[str, Any]:
    """Run an Automation Framework plan from a YAML file.

    Automation plans encode a full, repeatable scan pipeline (context, auth,
    spider, active scan, reporting) and are the recommended way to run
    reproducible engagements. Returns a plan ID for progress polling.

    Args:
        file_path: Absolute path to the plan YAML, resolved on the ZAP
            container's filesystem. Place the file in the shared work directory
            (``/zap/wrk``, mounted in both containers) so ZAP can read it.
    """
    data = await zap_client.execute_action(
        "automation", "runPlan", params={"filePath": file_path}
    )
    return {"status": "success", "plan_id": data.get("planId", data)}


@envelope
async def zap_automation_plan_progress(plan_id: str) -> Dict[str, Any]:
    """Get the progress of a running Automation Framework plan.

    Args:
        plan_id: The plan ID returned by ``zap_run_automation_plan``.
    """
    data = await zap_client.get_view(
        "automation", "planProgress", params={"planId": plan_id}
    )
    return {"status": "success", "plan_id": plan_id, "progress": data}
