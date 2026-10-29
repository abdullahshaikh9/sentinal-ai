import pytest

from app.services.scanning.policy import (
    DnsResolutionError,
    TargetValidationError,
    normalize_target_url,
    validate_resolved_addresses,
)


def test_normalize_target_url_removes_fragment_and_default_port() -> None:
    assert normalize_target_url(" HTTPS://Example.COM:443/path#fragment ") == "https://example.com/path"


@pytest.mark.parametrize(
    "target",
    ["ftp://example.com", "javascript:alert(1)", "http://localhost", "http://127.0.0.1", "http://user:pass@example.com"],
)
def test_rejects_unsafe_or_unsupported_targets(target: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target_url(target)


def test_rejects_private_dns_result_even_when_other_result_is_public() -> None:
    with pytest.raises(DnsResolutionError):
        validate_resolved_addresses(["93.184.216.34", "192.168.1.10"])


def test_rejects_cloud_metadata_address() -> None:
    with pytest.raises(DnsResolutionError):
        validate_resolved_addresses(["169.254.169.254"])


@pytest.mark.parametrize("address", ["100.64.0.1", "100.127.255.254", "192.0.2.1", "2001:db8::1"])
def test_rejects_non_global_special_purpose_addresses(address: str) -> None:
    with pytest.raises(DnsResolutionError):
        validate_resolved_addresses([address])


def test_accepts_globally_routable_ipv4_and_ipv6_addresses() -> None:
    assert validate_resolved_addresses(["93.184.216.34", "2001:4860:4860::8888"]) == [
        "93.184.216.34",
        "2001:4860:4860::8888",
    ]
