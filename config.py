"""Configuration management for the OWASP ZAP MCP Server.

Settings are loaded from the environment (optionally via a .env file) and are
validated eagerly at import time so that misconfiguration fails fast and loudly
rather than surfacing as confusing runtime errors mid-scan.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()


class ConfigurationError(RuntimeError):
    """Raised when the server is started with invalid or unsafe configuration."""


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env_str(name)
    if not raw:
        return default
    normalized = raw.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(
        f"{name} must be a boolean value (true/false), got {raw!r}"
    )


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = _env_str(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(
            f"{name} must be between {minimum} and {maximum} seconds, got {value}"
        )
    return value


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _env_str(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(
            f"{name} must be between {minimum} and {maximum}, got {value}"
        )
    return value


def _env_list(name: str) -> Tuple[str, ...]:
    raw = _env_str(name)
    if not raw:
        return ()
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def _validate_base_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigurationError(
            f"ZAP_BASE_URL must use http or https, got {url!r}"
        )
    if not parsed.netloc:
        raise ConfigurationError(f"ZAP_BASE_URL is missing a host, got {url!r}")
    return url.rstrip("/")


@dataclass(frozen=True)
class Settings:
    """Validated runtime configuration."""

    # --- ZAP REST API connection -------------------------------------------------
    zap_base_url: str = field(
        default_factory=lambda: _validate_base_url(
            _env_str("ZAP_BASE_URL", "http://localhost:8080")
        )
    )
    zap_api_key: str = field(default_factory=lambda: _env_str("ZAP_API_KEY"))

    # --- HTTP client behaviour ---------------------------------------------------
    request_timeout: float = field(
        default_factory=lambda: _env_float("REQUEST_TIMEOUT", 60.0, 1.0, 3600.0)
    )
    connect_timeout: float = field(
        default_factory=lambda: _env_float("CONNECT_TIMEOUT", 10.0, 1.0, 300.0)
    )
    max_retries: int = field(
        default_factory=lambda: _env_int("ZAP_MAX_RETRIES", 2, 0, 10)
    )
    retry_backoff_seconds: float = field(
        default_factory=lambda: _env_float("ZAP_RETRY_BACKOFF", 0.5, 0.0, 30.0)
    )
    max_response_items: int = field(
        default_factory=lambda: _env_int("ZAP_MAX_RESPONSE_ITEMS", 500, 1, 100_000)
    )

    # --- MCP server transport ----------------------------------------------------
    mcp_host: str = field(default_factory=lambda: _env_str("MCP_HOST", "127.0.0.1"))
    mcp_port: int = field(default_factory=lambda: _env_int("MCP_PORT", 8000, 1, 65535))

    # --- Target policy (applies to attack-capable tools) -------------------------
    # Optional allowlist of host suffixes that may be actively scanned. Left empty
    # by default because bug-bounty scope changes frequently; set it in CI or
    # long-running deployments to pin the engagement scope.
    target_allowlist: Tuple[str, ...] = field(
        default_factory=lambda: _env_list("ZAP_TARGET_ALLOWLIST")
    )
    # Blocks RFC1918 / loopback / link-local targets for attack-capable tools.
    # Off by default so local labs (juice-shop, DVWA, bodgeit) keep working.
    block_private_targets: bool = field(
        default_factory=lambda: _env_bool("ZAP_BLOCK_PRIVATE_TARGETS", False)
    )
    # Cloud metadata endpoints are always refused regardless of the flags above;
    # see policy.ALWAYS_BLOCKED_HOSTS. This cannot be disabled by configuration.

    # --- Filesystem boundaries ---------------------------------------------------
    # Directory (inside the ZAP container) that generated reports are written to.
    report_dir: str = field(
        default_factory=lambda: _env_str("ZAP_REPORT_DIR", "/zap/wrk")
    )

    # --- Operational mode --------------------------------------------------------
    # When true, a missing ZAP_API_KEY is tolerated (local development only).
    allow_insecure: bool = field(
        default_factory=lambda: _env_bool("ZAP_ALLOW_INSECURE", False)
    )

    def __post_init__(self) -> None:
        if not self.zap_api_key and not self.allow_insecure:
            raise ConfigurationError(
                "ZAP_API_KEY is not set. The ZAP API requires a key for all 'action' "
                "endpoints, and an unauthenticated API is remotely abusable. Set "
                "ZAP_API_KEY to the value ZAP was started with, or set "
                "ZAP_ALLOW_INSECURE=true to explicitly opt out (development only)."
            )
        if self.connect_timeout > self.request_timeout:
            raise ConfigurationError(
                "CONNECT_TIMEOUT must not exceed REQUEST_TIMEOUT "
                f"({self.connect_timeout} > {self.request_timeout})"
            )

    @property
    def redacted_summary(self) -> dict:
        """Configuration snapshot safe for logging (never includes the API key)."""
        return {
            "zap_base_url": self.zap_base_url,
            "zap_api_key_set": bool(self.zap_api_key),
            "request_timeout": self.request_timeout,
            "connect_timeout": self.connect_timeout,
            "max_retries": self.max_retries,
            "mcp_host": self.mcp_host,
            "mcp_port": self.mcp_port,
            "target_allowlist": list(self.target_allowlist) or "unrestricted",
            "block_private_targets": self.block_private_targets,
            "report_dir": self.report_dir,
            "allow_insecure": self.allow_insecure,
        }


settings = Settings()
