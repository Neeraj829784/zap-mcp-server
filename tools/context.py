"""Context and scope management MCP tools for OWASP ZAP.

Contexts group a set of URLs and hold the authentication, session, and scope
configuration used by authenticated scans. These tools configure ZAP state only.
"""
from typing import Any, Dict, Optional

from zap_client import envelope, zap_client


@envelope
async def zap_create_context(context_name: str) -> Dict[str, Any]:
    """Create a new context and return its numeric context ID.

    Args:
        context_name: A unique name for the context.
    """
    data = await zap_client.execute_action(
        "context", "newContext", params={"contextName": context_name}
    )
    return {
        "status": "success",
        "context_name": context_name,
        "context_id": data.get("contextId", data),
    }


@envelope
async def zap_include_in_context(context_name: str, regex: str) -> Dict[str, Any]:
    """Add an include regex to a context (defines what is in scope).

    Args:
        context_name: The context name.
        regex: A regex matching URLs to include (e.g. ``https://app\\..*``).
    """
    params = {"contextName": context_name, "regex": regex}
    data = await zap_client.execute_action("context", "includeInContext", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_exclude_from_context(context_name: str, regex: str) -> Dict[str, Any]:
    """Add an exclude regex to a context (e.g. logout/destructive URLs).

    Args:
        context_name: The context name.
        regex: A regex matching URLs to exclude.
    """
    params = {"contextName": context_name, "regex": regex}
    data = await zap_client.execute_action("context", "excludeFromContext", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_list_contexts() -> Dict[str, Any]:
    """List the names of all contexts in the current session."""
    data = await zap_client.get_view("context", "contextList")
    return {"status": "success", "contexts": data.get("contextList", data)}


@envelope
async def zap_get_context(context_name: str) -> Dict[str, Any]:
    """Get the full details of a context, including its numeric ID.

    Args:
        context_name: The context name.
    """
    data = await zap_client.get_view(
        "context", "context", params={"contextName": context_name}
    )
    return {"status": "success", "context": data.get("context", data)}


@envelope
async def zap_export_context(context_name: str, context_file: str) -> Dict[str, Any]:
    """Export a context to a file (path is relative to ZAP's home/contexts dir).

    Args:
        context_name: The context to export.
        context_file: Destination file path (inside the ZAP host).
    """
    params = {"contextName": context_name, "contextFile": context_file}
    data = await zap_client.execute_action("context", "exportContext", params=params)
    return {"status": "success", "result": data}


@envelope
async def zap_import_context(context_file: str) -> Dict[str, Any]:
    """Import a previously exported context from a file.

    Args:
        context_file: Source file path (inside the ZAP host).
    """
    params = {"contextFile": context_file}
    data = await zap_client.execute_action("context", "importContext", params=params)
    return {"status": "success", "result": data}
