"""User management MCP tools for OWASP ZAP authenticated scanning.

Covers Step 5 of ZAP's authenticated-scanning workflow: create a user in a
context, give it credentials, and enable it. These configure ZAP state only and
do not attack the target, so they are not gated by the target policy.
"""
from typing import Any, Dict, Optional

from zap_client import envelope, zap_client


@envelope
async def zap_new_user(context_id: str, name: str) -> Dict[str, Any]:
    """Create a new user in a context and return its user ID.

    Args:
        context_id: The numeric context ID the user belongs to.
        name: A human-readable label for the user.
    """
    params = {"contextId": context_id, "name": name}
    data = await zap_client.execute_action("users", "newUser", params=params)
    return {
        "status": "success",
        "context_id": context_id,
        "user_id": data.get("userId", data),
    }


@envelope
async def zap_set_user_credentials(
    context_id: str, user_id: str, auth_credentials_config_params: str
) -> Dict[str, Any]:
    """Set a user's authentication credentials.

    The credentials string is URL-encoded, ampersand-separated key/values whose
    keys depend on the context's authentication method. For form/JSON auth the
    keys are typically ``username`` and ``password``, e.g.
    ``username=alice%40example.com&password=s3cret``.

    Args:
        context_id: The numeric context ID.
        user_id: The user ID from ``zap_new_user``.
        auth_credentials_config_params: URL-encoded credentials string.
    """
    params = {
        "contextId": context_id,
        "userId": user_id,
        "authCredentialsConfigParams": auth_credentials_config_params,
    }
    data = await zap_client.execute_action(
        "users", "setAuthenticationCredentials", params=params
    )
    return {"status": "success", "user_id": user_id, "result": data}


@envelope
async def zap_set_user_enabled(
    context_id: str, user_id: str, enabled: bool = True
) -> Dict[str, Any]:
    """Enable or disable a user so ZAP will (or won't) authenticate as them.

    Args:
        context_id: The numeric context ID.
        user_id: The user ID.
        enabled: True to enable the user, False to disable.
    """
    params = {"contextId": context_id, "userId": user_id, "enabled": enabled}
    data = await zap_client.execute_action("users", "setUserEnabled", params=params)
    return {
        "status": "success",
        "user_id": user_id,
        "enabled": enabled,
        "result": data,
    }


@envelope
async def zap_list_users(context_id: Optional[str] = None) -> Dict[str, Any]:
    """List users in a context (or all users if none specified).

    Args:
        context_id: Optional numeric context ID to filter by.
    """
    params = {"contextId": context_id} if context_id else None
    data = await zap_client.get_view("users", "usersList", params=params)
    return {"status": "success", "users": data.get("usersList", data)}


@envelope
async def zap_get_user(context_id: str, user_id: str) -> Dict[str, Any]:
    """Get the full configuration of a single user.

    Args:
        context_id: The numeric context ID.
        user_id: The user ID.
    """
    params = {"contextId": context_id, "userId": user_id}
    data = await zap_client.get_view("users", "getUserById", params=params)
    return {"status": "success", "user": data}
