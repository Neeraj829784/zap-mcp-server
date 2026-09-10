"""Target authorization policy for attack-capable ZAP operations.

Active scanning is an attack. The official ZAP documentation is explicit that it
must only be run against targets you have permission to test. Because this
server is driven by a language model, a target URL can ultimately originate from
untrusted text (a scope file, a web page, a ticket), so the decision to attack is
enforced here in server-side code rather than left to the model.

Rules, in order of precedence:

1. Cloud metadata / orchestration endpoints are ALWAYS refused. There is no
   legitimate reason for an LLM-driven scanner to attack them and they are the
   classic pivot for credential theft. Not configurable.
2. If ``ZAP_TARGET_ALLOWLIST`` is set, only matching hosts may be attacked.
   Use this to pin an engagement scope.
3. If ``ZAP_BLOCK_PRIVATE_TARGETS`` is true, private/loopback/link-local hosts
   are refused. Off by default so local labs keep working.

Read-only views are intentionally not gated: they report existing state and
generate no traffic to the target.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from config import settings

# Hosts that are refused for attack-capable operations regardless of any
# allowlist or flag. These are cloud metadata / orchestration endpoints.
ALWAYS_BLOCKED_HOSTS = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure IMDS (IPv4)
        "fd00:ec2::254",  # AWS IMDS (IPv6)
        "metadata.google.internal",
        "metadata.goog",
    }
)

# IP networks that are refused for attack-capable operations regardless of flags.
ALWAYS_BLOCKED_NETWORKS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


class TargetNotAllowedError(Exception):
    """Raised when a target fails the authorization policy for an attack action."""


def _extract_host(target: str) -> str:
    """Return the lowercase hostname from a URL or bare host value."""
    candidate = (target or "").strip()
    if not candidate:
        raise TargetNotAllowedError("No target URL was provided.")

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = parsed.hostname
    if not host:
        raise TargetNotAllowedError(f"Could not parse a host from target {target!r}.")
    return host.lower()


def _resolved_ips(host: str) -> list:
    """Resolve a hostname to IP objects; empty list if it cannot be resolved.

    Resolution is best-effort. If DNS fails we do not hard-fail the policy check
    on that basis alone (ZAP itself will surface an unreachable target), but any
    address we *can* resolve is still evaluated against the block rules so that a
    hostname pointing at metadata/private space is caught.
    """
    ips = []
    try:
        ip_obj = ipaddress.ip_address(host)
        return [ip_obj]
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(host, None):
            addr = info[4][0]
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
    except socket.gaierror:
        return []
    return ips


def _is_always_blocked(host: str, ips: list) -> Optional[str]:
    if host in ALWAYS_BLOCKED_HOSTS:
        return f"{host} is a cloud metadata/orchestration endpoint"
    for ip in ips:
        for network in ALWAYS_BLOCKED_NETWORKS:
            if ip.version == network.version and ip in network:
                return f"{ip} is a cloud metadata endpoint"
    return None


def _is_private(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


def _matches_allowlist(host: str) -> bool:
    """True if host equals or is a subdomain of any allowlist entry."""
    for allowed in settings.target_allowlist:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def authorize_target(target: str) -> str:
    """Validate that ``target`` may be attacked; return the normalized host.

    Raises:
        TargetNotAllowedError: if the target violates the authorization policy.
    """
    host = _extract_host(target)
    ips = _resolved_ips(host)

    blocked_reason = _is_always_blocked(host, ips)
    if blocked_reason:
        raise TargetNotAllowedError(
            f"Refusing to attack {host!r}: {blocked_reason}. This restriction "
            "cannot be overridden."
        )

    if settings.target_allowlist and not _matches_allowlist(host):
        raise TargetNotAllowedError(
            f"Refusing to attack {host!r}: it is not in ZAP_TARGET_ALLOWLIST "
            f"({', '.join(settings.target_allowlist)}). Add the host to the "
            "allowlist to authorize testing against it."
        )

    if settings.block_private_targets and ips:
        if all(_is_private(ip) for ip in ips):
            raise TargetNotAllowedError(
                f"Refusing to attack {host!r}: it resolves to a private/loopback "
                "address and ZAP_BLOCK_PRIVATE_TARGETS is enabled."
            )

    return host
