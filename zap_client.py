"""Centralized asynchronous client for the OWASP ZAP REST API.

Design goals for production / bug-bounty use:

* A single, reused ``httpx.AsyncClient`` (created on startup, closed on
  shutdown) so connection pooling actually works instead of building and tearing
  down a client per request.
* Bounded, idempotent retries with backoff for transient connection/timeout
  errors -- ZAP under load occasionally drops connections and a scanner must be
  resilient to that.
* Typed exceptions carrying stable, machine-readable error codes.
* A helper (:func:`envelope`) that turns any result or exception into a uniform
  response shape so every MCP tool returns predictable, greppable output and
  never leaks the API key or raw stack traces.

Per the official docs, ZAP ``action`` and some ``other`` operations require the
API key. It is sent in both the ``X-ZAP-API-Key`` header and the ``apikey``
query parameter (ZAP accepts either); neither is ever logged.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, Optional

import httpx

from config import settings

logger = logging.getLogger("zap_mcp.client")


class ZAPClientError(Exception):
    """Base exception for ZAP client interactions.

    Attributes:
        code: A stable, machine-readable error code for programmatic handling.
        retryable: Whether the same call could reasonably succeed on retry.
    """

    code = "zap_client_error"
    retryable = False

    def __init__(self, message: str, code: Optional[str] = None, retryable: Optional[bool] = None):
        super().__init__(message)
        if code is not None:
            self.code = code
        if retryable is not None:
            self.retryable = retryable


class ZAPConnectionError(ZAPClientError):
    """Raised when ZAP cannot be reached."""

    code = "zap_unreachable"
    retryable = True


class ZAPTimeoutError(ZAPClientError):
    """Raised when an operation times out."""

    code = "zap_timeout"
    retryable = True


class ZAPAPIError(ZAPClientError):
    """Raised when ZAP returns an error response (non-200 or error JSON)."""

    code = "zap_api_error"
    retryable = False

    def __init__(self, message: str, code: Optional[str] = None, http_status: Optional[int] = None):
        super().__init__(message, code=code or "zap_api_error")
        self.http_status = http_status


class ZAPClient:
    """Async HTTP client wrapping ZAP JSON view/action endpoints.

    A single instance is shared across the process. Call :meth:`startup` before
    first use and :meth:`shutdown` on exit (wired into the MCP lifecycle).
    """

    def __init__(self) -> None:
        self.base_url = settings.zap_base_url
        self._api_key = settings.zap_api_key
        self._max_retries = settings.max_retries
        self._backoff = settings.retry_backoff_seconds
        self._limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
        self._timeout = httpx.Timeout(settings.request_timeout, connect=settings.connect_timeout)
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()

    # -- lifecycle ---------------------------------------------------------------

    async def startup(self) -> None:
        """Create the shared HTTP client (idempotent)."""
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    self._client = httpx.AsyncClient(
                        base_url=self.base_url,
                        timeout=self._timeout,
                        limits=self._limits,
                        headers={"Accept": "application/json"},
                    )
                    logger.info("ZAP HTTP client initialized for %s", self.base_url)

    async def shutdown(self) -> None:
        """Close the shared HTTP client (idempotent)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("ZAP HTTP client closed")

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            await self.startup()
        assert self._client is not None  # for type checkers
        return self._client

    # -- request helpers ---------------------------------------------------------

    def _query_params(self, params: Optional[Dict[str, Any]]) -> Dict[str, str]:
        clean = {k: str(v) for k, v in (params or {}).items() if v is not None}
        if self._api_key:
            clean["apikey"] = self._api_key
        return clean

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._api_key:
            headers["X-ZAP-API-Key"] = self._api_key
        return headers

    async def get_view(
        self, component: str, view_name: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Call a ZAP ``view`` endpoint (read-only query)."""
        return await self._request(f"/JSON/{component}/view/{view_name}/", params)

    async def execute_action(
        self, component: str, action_name: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Call a ZAP ``action`` endpoint (state-modifying operation)."""
        return await self._request(f"/JSON/{component}/action/{action_name}/", params)

    async def _request(self, endpoint: str, params: Optional[Dict[str, Any]]) -> Any:
        client = await self._get_client()
        query = self._query_params(params)
        headers = self._headers()

        last_exc: Optional[ZAPClientError] = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await client.get(endpoint, headers=headers, params=query)
            except httpx.ConnectError as exc:
                last_exc = ZAPConnectionError(
                    f"Failed to connect to ZAP at {self.base_url}: {exc}"
                )
            except httpx.TimeoutException as exc:
                last_exc = ZAPTimeoutError(
                    f"Request to ZAP timed out on {endpoint}: {exc}"
                )
            except httpx.RequestError as exc:
                last_exc = ZAPClientError(
                    f"Network error querying ZAP on {endpoint}: {exc}",
                    code="zap_network_error",
                    retryable=True,
                )
            else:
                return self._parse_response(endpoint, response)

            # We only reach here on a retryable transport error.
            if attempt < self._max_retries:
                delay = self._backoff * (2 ** attempt)
                logger.warning(
                    "ZAP request to %s failed (%s); retry %d/%d in %.1fs",
                    endpoint,
                    last_exc.code,
                    attempt + 1,
                    self._max_retries,
                    delay,
                )
                await asyncio.sleep(delay)

        assert last_exc is not None
        raise last_exc

    @staticmethod
    def _parse_response(endpoint: str, response: httpx.Response) -> Any:
        if response.status_code != 200:
            code = str(response.status_code)
            message = response.text
            try:
                err = response.json()
                message = err.get("message", message)
                code = err.get("code", code)
            except ValueError:
                pass
            raise ZAPAPIError(
                f"ZAP returned {response.status_code} for {endpoint}: {message}",
                code=str(code),
                http_status=response.status_code,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ZAPClientError(
                f"Failed to parse JSON from ZAP on {endpoint}: {response.text[:200]}",
                code="zap_bad_response",
            ) from exc


def envelope(fn: Callable) -> Callable:
    """Decorator wrapping an async tool so it returns a uniform result shape.

    Success:  ``{"status": "success", ...payload}``
    Failure:  ``{"status": "error", "code": <code>, "message": <str>,
                 "retryable": <bool>}``

    Any :class:`ZAPClientError` is converted to a structured error. Unexpected
    exceptions are caught too, so a single tool call can never crash the server;
    the message is included but never the API key (which lives only in headers/
    query params and is not part of exception text).
    """
    import functools

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        try:
            result = await fn(*args, **kwargs)
            if isinstance(result, dict) and "status" in result:
                return result
            return {"status": "success", "result": result}
        except ZAPClientError as exc:
            logger.info("Tool %s failed: %s (%s)", fn.__name__, exc, exc.code)
            return {
                "status": "error",
                "code": exc.code,
                "message": str(exc),
                "retryable": exc.retryable,
            }
        except Exception as exc:  # noqa: BLE001 - defensive boundary for tool calls
            logger.exception("Unexpected error in tool %s", fn.__name__)
            return {
                "status": "error",
                "code": "internal_error",
                "message": f"Unexpected error: {exc}",
                "retryable": False,
            }

    return wrapper


# Shared singleton instance used by all tool modules.
zap_client = ZAPClient()


def cap_list(items: Any) -> Dict[str, Any]:
    """Bound a potentially large list to ``settings.max_response_items``.

    Returns a dict with the (possibly truncated) items plus metadata so the
    caller always knows the true size and whether truncation occurred. This
    prevents a scan of a large target from flooding the LLM's context window.
    """
    if not isinstance(items, list):
        return {"items": items, "total": None, "truncated": False}
    total = len(items)
    limit = settings.max_response_items
    if total > limit:
        return {"items": items[:limit], "total": total, "returned": limit, "truncated": True}
    return {"items": items, "total": total, "returned": total, "truncated": False}
