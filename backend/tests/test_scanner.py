from datetime import UTC, datetime, timedelta

from app.services.scanning.scanner import (
    FetchResponse,
    ResponseTooLargeError,
    ScanTransportError,
    WebsiteScanner,
)


class FakeFetcher:
    def __init__(self, responses: dict[str, FetchResponse | Exception]) -> None:
        self.responses = responses
        self.requested: list[tuple[str, list[str]]] = []

    def fetch(self, url: str, addresses: list[str]) -> FetchResponse:
        self.requested.append((url, addresses))
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        return result


def resolver(hostname: str, port: int) -> list[str]:
    assert hostname in {"public.example", "secure.example"}
    return ["93.184.216.34"]


def test_scanner_follows_safe_redirect_and_generates_evidence_findings() -> None:
    fetcher = FakeFetcher(
        {
            "http://public.example/": FetchResponse(302, {"location": "https://secure.example/"}, [], b""),
            "https://secure.example/": FetchResponse(
                200,
                {"content-type": "text/html"},
                ["session=abc; Path=/"],
                b"<html></html>",
                tls_valid=True,
                tls_expires_at=datetime.now(UTC) + timedelta(days=10),
            ),
        }
    )
    report = WebsiteScanner(resolver=resolver, fetcher=fetcher).scan("http://public.example")

    assert report.status == "completed"
    assert report.redirects == ["https://secure.example/"]
    assert report.risk_score > 0
    assert {finding.stable_id for finding in report.findings} >= {
        "tls.certificate-expiring",
        "headers.hsts-missing",
        "cookie.secure-missing",
        "cookie.httponly-missing",
    }
    assert all(finding.evidence for finding in report.findings)
    cookie_finding = next(finding for finding in report.findings if finding.stable_id == "cookie.httponly-missing")
    assert cookie_finding.evidence_data["cookie_name"] == "session"
    assert cookie_finding.evidence_data["observed_attributes"] == ["path"]
    assessment = cookie_finding.evidence_data["assessment"]
    assert assessment["verification_status"] == "not_attempted"
    assert assessment["root_cause"].startswith("The server-side cause is not determined")
    assert assessment["references"]


def test_cookie_with_httponly_is_not_reported() -> None:
    fetcher = FakeFetcher({
        "https://secure.example/": FetchResponse(
            200,
            {"content-type": "text/html"},
            ["session=redacted; Path=/; HttpOnly; Secure; SameSite=Lax"],
            b"<html></html>",
            tls_valid=True,
        )
    })
    report = WebsiteScanner(resolver=resolver, fetcher=fetcher).scan("https://secure.example")
    assert not any(finding.stable_id == "cookie.httponly-missing" for finding in report.findings)


def test_duplicate_cookie_headers_do_not_duplicate_logical_findings_or_score() -> None:
    fetcher = FakeFetcher({
        "https://secure.example/": FetchResponse(
            200,
            {"content-type": "text/html"},
            ["session=one; Path=/", "preference=two; Path=/"],
            b"<html></html>",
            tls_valid=True,
        )
    })
    report = WebsiteScanner(resolver=resolver, fetcher=fetcher).scan("https://secure.example")
    httponly = [finding for finding in report.findings if finding.stable_id == "cookie.httponly-missing"]
    assert len(httponly) == 2
    assert len({finding.dedup_key for finding in httponly}) == 2
    assert all("one" not in finding.evidence for finding in httponly)
    assert all("two" not in finding.evidence for finding in httponly)


def test_scanner_does_not_follow_unsafe_redirect() -> None:
    fetcher = FakeFetcher(
        {"https://public.example/": FetchResponse(302, {"location": "http://127.0.0.1/admin"}, [], b"")}
    )
    report = WebsiteScanner(resolver=resolver, fetcher=fetcher).scan("https://public.example")

    assert report.status == "partial"
    assert [request[0] for request in fetcher.requested] == ["https://public.example/"]
    assert report.findings[0].stable_id == "redirect.destination-blocked"


def test_scanner_distinguishes_incomplete_checks_from_findings() -> None:
    too_large = FakeFetcher({"https://public.example/": ResponseTooLargeError()})
    timed_out = FakeFetcher({"https://public.example/": ScanTransportError()})

    large_report = WebsiteScanner(resolver=resolver, fetcher=too_large).scan("https://public.example")
    timeout_report = WebsiteScanner(resolver=resolver, fetcher=timed_out).scan("https://public.example")

    assert large_report.findings[0].stable_id == "scan.response-too-large"
    assert timeout_report.findings[0].stable_id == "scan.request-incomplete"
    assert large_report.risk_score == 0


def test_initial_dns_failure_is_not_classified_as_a_redirect() -> None:
    def failing_resolver(hostname: str, port: int) -> list[str]:
        from app.services.scanning.policy import DnsResolutionError
        raise DnsResolutionError("resolution failed")

    report = WebsiteScanner(resolver=failing_resolver, fetcher=FakeFetcher({})).scan("https://public.example")
    assert report.status == "failed"
    assert report.error_message is not None
    assert not any(finding.stable_id == "redirect.destination-blocked" for finding in report.findings)


def test_csp_present_and_absent_are_recorded_as_observed_rule_results() -> None:
    present = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(200, {"content-security-policy": "default-src 'self'"}, [], b"ok", tls_valid=True),
    })).scan("https://secure.example")
    absent = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(200, {}, [], b"ok", tls_valid=True),
    })).scan("https://secure.example")

    assert present.check_details["rule_results"]["headers.csp"] == "present"
    assert not any(item.stable_id == "headers.csp-missing" for item in present.findings)
    csp = next(item for item in absent.findings if item.stable_id == "headers.csp-missing")
    assert csp.evidence == "The final response did not include the content-security-policy header."
    assert csp.evidence_data["assessment"]["impact"]
    assert absent.check_details["rule_results"]["headers.csp"] == "missing"


def test_equivalent_frame_ancestors_suppresses_duplicate_missing_x_frame_options() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(200, {
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        }, [], b"ok", tls_valid=True),
    })).scan("https://secure.example")

    assert report.check_details["rule_results"]["headers.frame-options"] == "skipped"
    assert not any(item.stable_id == "headers.frame-options-missing" for item in report.findings)


def test_empty_or_ineffective_header_values_are_not_counted_as_present() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(200, {
            "strict-transport-security": "max-age=0",
            "x-content-type-options": "nosniffing",
            "content-security-policy": "",
        }, [], b"ok", tls_valid=True),
    })).scan("https://secure.example")

    assert report.check_details["rule_results"]["headers.hsts"] == "invalid"
    assert report.check_details["rule_results"]["headers.content-type-options"] == "invalid"
    assert report.check_details["rule_results"]["headers.csp"] == "missing"
    assert {"headers.hsts-invalid", "headers.content-type-options-invalid", "headers.csp-missing"} <= {item.stable_id for item in report.findings}


def test_hsts_absence_is_not_reported_for_plain_http_response() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "http://public.example/": FetchResponse(200, {}, [], b"ok"),
    })).scan("http://public.example")

    assert report.check_details["rule_results"]["headers.hsts"] == "skipped"
    assert not any(item.stable_id == "headers.hsts-missing" for item in report.findings)
    assert any(item.stable_id == "transport.https-not-enforced" for item in report.findings)


def test_intermediate_redirect_status_is_preserved_separately_from_final_headers() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "http://public.example/": FetchResponse(301, {"location": "https://secure.example/?token=private"}, [], b""),
        "https://secure.example/?token=private": FetchResponse(200, {"content-security-policy": "default-src 'self'"}, [], b"ok", tls_valid=True),
    })).scan("http://public.example")

    assert report.check_details["redirect_observations"] == [{
        "status": 301,
        "source": "http://public.example/",
        "destination": "https://secure.example/",
    }]
    assert report.check_details["response_status"] == 200
    assert "private" not in str(report.check_details)
    assert report.check_details["response_headers"]["content-security-policy"] == "default-src 'self'"


def test_forbidden_challenge_response_does_not_create_header_absence_findings() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(403, {"server": "cloudflare"}, [], b"challenge", tls_valid=True),
    })).scan("https://secure.example")

    assert report.status == "partial"
    assert report.checks["headers"] == "inconclusive"
    assert report.checks["cookies"] == "inconclusive"
    assert report.check_details["response_status"] == 403
    assert [item.stable_id for item in report.findings] == ["scan.access-restricted"]
    assert report.risk_score == 0


def test_explicit_cloudflare_challenge_marker_makes_response_dependent_checks_inconclusive() -> None:
    report = WebsiteScanner(resolver=resolver, fetcher=FakeFetcher({
        "https://secure.example/": FetchResponse(200, {"cf-mitigated": "challenge"}, [], b"challenge", tls_valid=True),
    })).scan("https://secure.example")

    assert report.status == "partial"
    assert report.checks["headers"] == "inconclusive"
    assert report.findings[0].stable_id == "scan.access-restricted"
    assert "cf-mitigated: challenge" in report.findings[0].evidence
    assert not any(item.stable_id.startswith("headers.") for item in report.findings)
