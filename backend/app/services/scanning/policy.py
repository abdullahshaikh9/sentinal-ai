"""SSRF-safe policy helpers for authorized, non-destructive assessments."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import SplitResult, urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """Raised when a target is not a safe HTTP(S) public target."""


class DnsResolutionError(TargetValidationError):
    """Raised when a hostname cannot be resolved to safe public addresses."""


MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 3
MAX_CONCURRENT_REQUESTS = 4
METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def normalize_target_url(raw_url: str) -> str:
    """Normalize and syntactically validate an HTTP(S) URL."""
    if not isinstance(raw_url, str):
        raise TargetValidationError("Target URL must be a string.")
    value = raw_url.strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise TargetValidationError("Target URL must be between 1 and 2048 characters.")
    if any(ord(character) < 32 for character in value):
        raise TargetValidationError("Target URL contains invalid control characters.")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// target URLs are allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("Target URLs must not contain embedded credentials.")
    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a hostname.")

    try:
        ascii_host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise TargetValidationError("Target URL contains an invalid hostname or port.") from exc
    if not ascii_host or ascii_host == "localhost" or ascii_host.endswith(".local"):
        raise TargetValidationError("Internal hostnames are not allowed as scan targets.")
    try:
        literal_address = ipaddress.ip_address(ascii_host)
    except ValueError:
        literal_address = None
    if literal_address is not None and is_unsafe_ip(literal_address):
        raise TargetValidationError("Only globally routable public addresses are allowed; unsafe addresses are rejected.")

    host_for_netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    default_port = 443 if scheme == "https" else 80
    netloc = host_for_netloc if port in (None, default_port) else f"{host_for_netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def is_unsafe_ip(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is not a publicly routable assessment target."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    mapped = parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) else None
    candidates = [parsed] if mapped is None else [parsed, mapped]
    return any(
        candidate in METADATA_ADDRESSES
        # Some special-purpose ranges (for example shared carrier-grade NAT)
        # are neither private nor reserved according to ipaddress.
        or not candidate.is_global
        or candidate.is_loopback
        or candidate.is_private
        or candidate.is_link_local
        or candidate.is_reserved
        or candidate.is_multicast
        or candidate.is_unspecified
        for candidate in candidates
    )


def validate_resolved_addresses(addresses: list[str]) -> list[str]:
    """Validate every DNS result to prevent mixed-safe/unsafe rebinding targets."""
    unique_addresses = list(dict.fromkeys(addresses))
    if not unique_addresses:
        raise DnsResolutionError("Target hostname did not resolve to an address.")
    if any(is_unsafe_ip(address) for address in unique_addresses):
        raise DnsResolutionError("Target hostname resolved to a private or otherwise unsafe address.")
    return unique_addresses


def resolve_public_addresses(hostname: str, port: int) -> list[str]:
    """Resolve a hostname and reject unsafe results before opening a socket."""
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise DnsResolutionError("Target hostname could not be resolved.") from exc
    addresses = [result[4][0] for result in results]
    return validate_resolved_addresses(addresses)


def split_target_url(url: str) -> tuple[SplitResult, int]:
    """Return parsed target data with a scheme-appropriate default port."""
    parsed = urlsplit(url)
    return parsed, parsed.port or (443 if parsed.scheme == "https" else 80)

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 3
MAX_CONCURRENT_REQUESTS = 4


def assessment_scope_notice() -> str:
    return "Assess only publicly accessible targets that the user is authorized to assess."

