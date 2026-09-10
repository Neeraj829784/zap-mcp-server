"""Authentication configuration MCP tools for OWASP ZAP.

These tools cover Step 2-4 of ZAP's authenticated-scanning workflow: choosing an
authentication method for a context, supplying its configuration, and telling
ZAP how to recognise a logged-in vs logged-out response. User credentials and
forced-user mode live in ``tools.users`` and ``tools.forced_user`` respectively.

None of these operations attack the target, so they are not gated by the target
policy; they only configure ZAP's own context state.
"""
from typing import Any, Dict, Optional

from zap_client import envelope, zap_client


@envelope
async def zap_get_auth_methods() -> Dict[str, Any]:
    """List the authentication methods supported by this ZAP instance.

    Returns method names such as ``formBasedAuthentication``,
    ``jsonBasedAuthentication``, ``scriptBasedAuthentication``,
    ``httpAuthentication``, and ``manualAuthentication``.
    """
    data = await zap_client.get_view(
        "authentication", "getSupportedAuthenticationMethods"
    )
    # ZAP 2.17 returns the list under "supportedMethods".
    methods = data.get("supportedMethods")
    if methods is None:
        # Backwards/forwards compatibility with alternate key spellings.
        methods = data.get("supportedAuthenticationMethods", [])
    return {"status": "success", "methods": methods}


@envelope
async def zap_get_auth_method_config_params(auth_method_name: str) -> Dict[str, Any]:
    """List the configuration parameters required by an authentication method.

    Use this before ``zap_set_authentication_method`` to discover exactly which
    parameters a method (e.g. ``formBasedAuthentication``) expects.

    Args:
        auth_method_name: The authentication method name, e.g.
            ``formBasedAuthentication``.
    """
    data = await zap_client.get_view(
        "authentication",
        "getAuthenticationMethodConfigParams",
        params={"authMethodName": auth_method_name},
    )
    return {
        "status": "success",
        "auth_method": auth_method_name,
        "config_params": data.get("methodConfigParams", data),
    }


@envelope
async def zap_set_authentication_method(
    context_id: str,
    auth_method_name: str,
    auth_method_config_params: Optional[str] = None,
) -> Dict[str, Any]:
    """Set the authentication method for a context.

    This is the core of authenticated scanning. The config params string is a
    URL-encoded, ampersand-separated key/value list whose keys depend on the
    method. For ``formBasedAuthentication`` the keys are ``loginUrl`` and
    ``loginRequestData`` (with ``loginRequestData`` itself URL-encoded), e.g.::

        loginUrl=https://app/login&loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D

    Use ``zap_get_auth_method_config_params`` to discover the required keys.

    Args:
        context_id: The numeric context ID to configure.
        auth_method_name: e.g. ``formBasedAuthentication`` or
            ``jsonBasedAuthentication``.
        auth_method_config_params: URL-encoded config string for the method.
    """
    params = {
        "contextId": context_id,
        "authMethodName": auth_method_name,
        "authMethodConfigParams": auth_method_config_params,
    }
    data = await zap_client.execute_action(
        "authentication", "setAuthenticationMethod", params=params
    )
    return {"status": "success", "context_id": context_id, "result": data}


@envelope
async def zap_get_authentication_method(context_id: str) -> Dict[str, Any]:
    """Get the currently configured authentication method for a context.

    Args:
        context_id: The numeric context ID.
    """
    data = await zap_client.get_view(
        "authentication", "getAuthenticationMethod", params={"contextId": context_id}
    )
    return {"status": "success", "context_id": context_id, "method": data}


@envelope
async def zap_set_logged_in_indicator(
    context_id: str, logged_in_regex: str
) -> Dict[str, Any]:
    """Set the regex that marks a response as authenticated.

    Args:
        context_id: The numeric context ID.
        logged_in_regex: Regex present only when logged in
            (e.g. ``\\Q<a href="logout">Logout</a>\\E``).
    """
    params = {"contextId": context_id, "loggedInIndicatorRegex": logged_in_regex}
    data = await zap_client.execute_action(
        "authentication", "setLoggedInIndicator", params=params
    )
    return {"status": "success", "context_id": context_id, "result": data}


@envelope
async def zap_set_logged_out_indicator(
    context_id: str, logged_out_regex: str
) -> Dict[str, Any]:
    """Set the regex that marks a response as logged out.

    ZAP needs at least one of the logged-in / logged-out indicators to detect
    when re-authentication is required.

    Args:
        context_id: The numeric context ID.
        logged_out_regex: Regex present only when logged out
            (e.g. a redirect to ``/login``).
    """
    params = {"contextId": context_id, "loggedOutIndicatorRegex": logged_out_regex}
    data = await zap_client.execute_action(
        "authentication", "setLoggedOutIndicator", params=params
    )
    return {"status": "success", "context_id": context_id, "result": data}
