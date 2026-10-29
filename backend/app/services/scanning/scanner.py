"""Bounded, non-destructive HTTP(S) assessment with DNS pinning."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

from app.services.risk import calculate_risk_score
from app.services.scanning.policy import (
    MAX_CONCURRENT_REQUESTS,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    TargetValidationError,
    normalize_target_url,
    resolve_public_addresses,
    split_target_url,
)


class ScanTransportError(RuntimeError):
    """A bounded request could not complete safely."""


class TlsValidationError(ScanTransportError):
    """The target's HTTPS certificate could not be validated."""


class ResponseTooLargeError(ScanTransportError):
    """The response exceeded the configured body limit."""


@dataclass(frozen=True)
class FindingResult:
    stable_id: str
    title: str
    severity: str
    category: str
    evidence: str
    explanation: str
    remediation: str
    confidence: str
    dedup_key: str | None = None
    evidence_data: dict[str, object] | None = None


@dataclass(frozen=True)
class FetchResponse:
    status_code: int
    headers: dict[str, str]
    set_cookies: list[str]
    body: bytes
    tls_valid: bool | None = None
    tls_expires_at: datetime | None = None


@dataclass(frozen=True)
class ScanReport:
    normalized_url: str
    status: str
    findings: list[FindingResult] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "none"
    error_message: str | None = None
    redirects: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    check_details: dict[str, object] = field(default_factory=dict)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except ssl.SSLError:
            raw_socket.close()
            raise


class PinnedHttpFetcher:
    """Fetch through a previously validated IP so DNS cannot rebind between checks."""

    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    _request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def fetch(self, url: str, addresses: list[str]) -> FetchResponse:
        parsed, port = split_target_url(url)
        address = addresses[0]
        connection: http.client.HTTPConnection | http.client.HTTPSConnection
        if parsed.scheme == "https":
            connection = _PinnedHTTPSConnection(parsed.hostname or "", port, address, self.timeout)
        else:
            connection = _PinnedHTTPConnection(parsed.hostname or "", port, address, self.timeout)

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        try:
            deadline = time.monotonic() + self.timeout
            with self._request_slots:
                connection.timeout = max(0.001, deadline - time.monotonic())
                connection.request(
                    "GET",
                    path,
                    headers={
                        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                        "Connection": "close",
                        "Host": parsed.hostname or "",
                        "User-Agent": "SentinelAI-SecurityAssessment/1.0",
                    },
                )
                connection.timeout = max(0.001, deadline - time.monotonic())
                response = connection.getresponse()
                content_length = response.getheader("Content-Length")
                if content_length and int(content_length) > self.max_response_bytes:
                    raise ResponseTooLargeError("Target response exceeded the configured size limit.")
                body = self._read_body(response, deadline)
                tls_expires_at = self._certificate_expiry(connection) if parsed.scheme == "https" else None
                return FetchResponse(
                    status_code=response.status,
                    headers={key.lower(): value for key, value in response.getheaders() if key.lower() != "set-cookie"},
                    set_cookies=response.headers.get_all("Set-Cookie") or [],
                    body=body,
                    tls_valid=parsed.scheme == "https",
                    tls_expires_at=tls_expires_at,
                )
        except ResponseTooLargeError:
            raise
        except ssl.SSLError as exc:
            raise TlsValidationError("Target HTTPS certificate could not be validated.") from exc
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise ScanTransportError("Target request could not be completed within the safety limits.") from exc
        finally:
            connection.close()

    def _read_body(self, response: http.client.HTTPResponse, deadline: float) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total <= self.max_response_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScanTransportError("Target request exceeded the configured timeout.")
            raw_socket = getattr(getattr(response, "fp", None), "raw", None)
            socket_object = getattr(raw_socket, "_sock", None)
            if socket_object is not None:
                socket_object.settimeout(remaining)
            chunk = response.read(min(64 * 1024, self.max_response_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > self.max_response_bytes:
                raise ResponseTooLargeError("Target response exceeded the configured size limit.")
        raise ResponseTooLargeError("Target response exceeded the configured size limit.")

    @staticmethod
    def _certificate_expiry(connection: http.client.HTTPConnection) -> datetime | None:
        sock = connection.sock
        if not isinstance(sock, ssl.SSLSocket):
            return None
        certificate = sock.getpeercert()
        not_after = certificate.get("notAfter")
        if not not_after:
            return None
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)


def _finding(
    stable_id: str,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    explanation: str,
    remediation: str,
    confidence: str = "high",
    *,
    dedup_key: str | None = None,
    evidence_data: dict[str, object] | None = None,
) -> FindingResult:
    references_by_rule = {
        "headers.hsts-missing": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        "headers.hsts-invalid": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        "headers.csp-missing": ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
        "headers.content-type-options-missing": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        "headers.content-type-options-invalid": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        "headers.referrer-policy-missing": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
        "headers.frame-options-missing": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
        "headers.permissions-policy-missing": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"],
        "cookie.secure-missing": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
        "cookie.httponly-missing": ["https://owasp.org/www-community/HttpOnly"],
        "cookie.samesite-missing": ["https://owasp.org/www-community/SameSite"],
        "transport.https-not-enforced": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    }
    if stable_id == "transport.https-not-enforced":
        impact = "Traffic to the observed HTTP endpoint is not encrypted in transit; practical exposure depends on the data and whether sensitive operations are available over HTTP."
    elif stable_id.startswith("headers.") or stable_id.startswith("cookie."):
        impact = "This response-level configuration gap can reduce a browser defense in relevant conditions; it does not establish that exploitation occurred or is possible."
    elif severity == "info":
        impact = "No vulnerability impact is inferred; this record describes scan coverage or an observation only."
    else:
        impact = "Potential impact depends on application behavior and exposure; validate the observation in context before assigning business impact."
    assessment = {
        "impact": impact,
        "root_cause": "The server-side cause is not determined by this bounded HTTP response assessment.",
        "verification_status": "not_attempted",
        "references": references_by_rule.get(stable_id, []),
    }
    saved_evidence = dict(evidence_data or {})
    saved_evidence["assessment"] = assessment
    return FindingResult(
        stable_id,
        title,
        severity,
        category,
        evidence,
        explanation,
        remediation,
        confidence,
        dedup_key or stable_id,
        saved_evidence,
    )


def _header_finding(response: FetchResponse, name: str, stable_id: str, title: str, remediation: str) -> FindingResult | None:
    if response.headers.get(name.lower(), "").strip():
        return None
    return _finding(
        stable_id,
        title,
        "low",
        "security-header",
        f"The final response did not include the {name} header.",
        "This is a confirmed configuration observation, not proof that the target is exploitable.",
        remediation,
    )


def _cookie_findings(response: FetchResponse) -> list[FindingResult]:
    findings: list[FindingResult] = []
    for raw_cookie in response.set_cookies:
        parts = [part.strip() for part in raw_cookie.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip()[:100]
        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        observed_attributes = sorted(attributes)
        evidence_data = {"cookie_name": cookie_name, "observed_attributes": observed_attributes}
        if "secure" not in attributes:
            findings.append(
                _finding(
                    "cookie.secure-missing",
                    "Cookie is missing the Secure attribute",
                    "medium",
                    "cookie",
                    f"Cookie {cookie_name!r} was set without Secure on an HTTPS response.",
                    "A cookie without Secure may be sent over an unencrypted connection if HTTP is reachable.",
                    "Set Secure on cookies that should only be sent over HTTPS and redirect HTTP to HTTPS.",
                    dedup_key=f"cookie.secure-missing:{cookie_name}",
                    evidence_data=evidence_data,
                )
            )
        if "httponly" not in attributes:
            findings.append(
                _finding(
                    "cookie.httponly-missing",
                    "Cookie is missing the HttpOnly attribute",
                    "low",
                    "cookie",
                    f"Cookie {cookie_name!r} was set without HttpOnly.",
                    "This is an observable cookie configuration gap; it does not by itself prove script access or exploitation.",
                    "Set HttpOnly on cookies that do not need to be read by client-side scripts.",
                    dedup_key=f"cookie.httponly-missing:{cookie_name}",
                    evidence_data=evidence_data,
                )
            )
        if not any(attribute.startswith("samesite") for attribute in attributes):
            findings.append(
                _finding(
                    "cookie.samesite-missing",
                    "Cookie is missing the SameSite attribute",
                    "low",
                    "cookie",
                    f"Cookie {cookie_name!r} was set without SameSite.",
                    "SameSite controls whether browsers attach the cookie in cross-site contexts.",
                    "Set an appropriate SameSite policy, commonly Lax or Strict unless cross-site use is required.",
                    dedup_key=f"cookie.samesite-missing:{cookie_name}",
                    evidence_data=evidence_data,
                )
            )
    return findings


def deduplicate_findings(findings: list[FindingResult]) -> list[FindingResult]:
    unique: list[FindingResult] = []
    seen: set[str] = set()
    for finding in findings:
        key = finding.dedup_key or finding.stable_id
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _display_url(url: str) -> str:
    """Persist only the origin/path in reports; query strings can contain secrets."""
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _header_rule_results(response: FetchResponse, final_scheme: str) -> dict[str, str]:
    rules = {
        "headers.hsts": "strict-transport-security",
        "headers.csp": "content-security-policy",
        "headers.content-type-options": "x-content-type-options",
        "headers.referrer-policy": "referrer-policy",
        "headers.frame-options": "x-frame-options",
        "headers.permissions-policy": "permissions-policy",
    }
    results: dict[str, str] = {}
    for rule, header in rules.items():
        value = response.headers.get(header, "").strip()
        if rule == "headers.hsts" and final_scheme != "https":
            results[rule] = "skipped"
        elif rule == "headers.frame-options" and re.search(r"(?i)(?:^|;)\s*frame-ancestors\b", response.headers.get("content-security-policy", "")):
            results[rule] = "skipped"
        elif not value:
            results[rule] = "missing"
        elif rule == "headers.hsts":
            match = re.search(r"(?i)(?:^|;)\s*max-age\s*=\s*(\d+)", value)
            results[rule] = "present" if match and int(match.group(1)) > 0 else "invalid"
        elif rule == "headers.content-type-options":
            results[rule] = "present" if value.lower() == "nosniff" else "invalid"
        else:
            results[rule] = "present"
    if final_scheme == "https":
        for index, cookie in enumerate(response.set_cookies):
            parts = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
            results[f"cookies.{index}.secure"] = "present" if "secure" in parts else "missing"
            results[f"cookies.{index}.httponly"] = "present" if "httponly" in parts else "missing"
            results[f"cookies.{index}.samesite"] = "present" if "samesite" in parts else "missing"
    return results


def _safe_response_details(response: FetchResponse, final_url: str, redirects: list[dict[str, object]], final_scheme: str) -> dict[str, object]:
    allowed_headers = (
        "content-type", "strict-transport-security", "content-security-policy",
        "x-content-type-options", "referrer-policy", "x-frame-options", "permissions-policy",
    )
    headers: dict[str, str] = {}
    for name in allowed_headers:
        value = response.headers.get(name)
        if value:
            value = value[:1000]
            value = re.sub(r"(?i)nonce-[A-Za-z0-9_+/=-]+", "nonce-[redacted]", value)
            headers[name] = value
    return {
        "response_status": response.status_code,
        "final_url": _display_url(final_url),
        "response_headers": headers,
        "redirect_observations": redirects,
        "rule_results": _header_rule_results(response, final_scheme),
        "scanner_version": 2,
    }


class WebsiteScanner:
    def __init__(self, resolver=resolve_public_addresses, fetcher: PinnedHttpFetcher | None = None) -> None:
        self.resolver = resolver
        self.fetcher = fetcher or PinnedHttpFetcher()

    def scan(self, target_url: str) -> ScanReport:
        normalized_url = normalize_target_url(target_url)
        current_url = normalized_url
        redirects: list[str] = []
        redirect_observations: list[dict[str, object]] = []
        dns_observations: list[dict[str, object]] = []
        response: FetchResponse | None = None
        findings: list[FindingResult] = []
        check_details: dict[str, object] = {}
        checks = {
            "dns": "inconclusive",
            "transport": "inconclusive",
            "redirects": "completed",
            "tls": "skipped",
            "headers": "skipped",
            "cookies": "skipped",
        }
        status = "completed"
        error_message: str | None = None

        for _ in range(MAX_REDIRECTS + 1):
            parsed, port = split_target_url(current_url)
            try:
                addresses = self.resolver(parsed.hostname or "", port)
                checks["dns"] = "completed"
                dns_observations.append({"hostname": parsed.hostname or "", "validated_public_addresses": addresses[:8]})
                response = self.fetcher.fetch(current_url, addresses)
                checks["transport"] = "completed"
                checks["tls"] = "completed" if parsed.scheme == "https" else "skipped"
            except TargetValidationError as exc:
                if redirects:
                    findings.append(_finding(
                        "redirect.destination-blocked",
                        "Redirect destination was blocked by SSRF policy",
                        "info",
                        "redirect",
                        str(exc),
                        "The scanner refused to follow a redirect that did not meet the public-target policy.",
                        "Review the redirect destination and ensure it is an authorized public HTTPS target.",
                    ))
                    checks["redirects"] = "inconclusive"
                    status = "partial"
                    error_message = "The redirect chain could not be completed because a destination failed the safety policy."
                else:
                    checks["dns"] = "failed"
                    status = "failed"
                    error_message = "The target could not be resolved or did not meet the public-target policy."
                break
            except TlsValidationError:
                findings.append(
                    _finding(
                        "tls.certificate-invalid",
                        "HTTPS certificate could not be validated",
                        "medium",
                        "transport",
                        f"TLS validation failed while connecting to {current_url}.",
                        "The scanner could not establish a certificate-validating HTTPS connection.",
                        "Install a valid, currently trusted certificate covering the target hostname.",
                    )
                )
                checks["transport"] = "failed"
                checks["tls"] = "failed"
                status = "partial"
                error_message = "The assessment stopped because the target HTTPS certificate could not be validated."
                break
            except ResponseTooLargeError:
                findings.append(
                    _finding(
                        "scan.response-too-large",
                        "Response exceeded the scanner size limit",
                        "info",
                        "scan-limit",
                        f"The response exceeded {MAX_RESPONSE_BYTES} bytes.",
                        "The scanner stopped reading to protect resource limits; content-based checks are incomplete.",
                        "No remediation is inferred from this check; review the target response size if a complete assessment is required.",
                    )
                )
                checks["transport"] = "inconclusive"
                checks["headers"] = "inconclusive"
                checks["cookies"] = "inconclusive"
                status = "partial"
                error_message = "The response was too large to complete all bounded checks."
                break
            except ScanTransportError:
                findings.append(
                    _finding(
                        "scan.request-incomplete",
                        "Request could not be completed within scanner limits",
                        "info",
                        "scan-limit",
                        "The target did not provide a complete response before the configured timeout or transport limit.",
                        "Security checks that require a complete response could not be completed.",
                        "Retry the assessment when the authorized target is available and responsive.",
                        confidence="high",
                    )
                )
                checks["transport"] = "failed"
                checks["headers"] = "inconclusive"
                checks["cookies"] = "inconclusive"
                status = "failed"
                error_message = "The target did not provide a complete response within the scanner safety limits."
                break

            location = response.headers.get("location") if response else None
            if response and response.status_code in {301, 302, 303, 307, 308} and location:
                if len(redirects) >= MAX_REDIRECTS:
                    findings.append(
                        _finding(
                            "redirect.limit-reached",
                            "Redirect limit reached",
                            "info",
                            "redirect",
                            f"The response chain exceeded the limit of {MAX_REDIRECTS} redirects.",
                            "The scanner stopped following redirects; the final target could not be assessed.",
                            "Reduce redirect hops for predictable, bounded navigation.",
                        )
                    )
                    checks["redirects"] = "inconclusive"
                    status = "partial"
                    error_message = "The redirect chain exceeded the scanner safety limit."
                    break
                try:
                    next_url = normalize_target_url(urljoin(current_url, location))
                except TargetValidationError as exc:
                    findings.append(
                        _finding(
                            "redirect.destination-blocked",
                            "Redirect destination was blocked by SSRF policy",
                            "info",
                            "redirect",
                            str(exc),
                            "The scanner refused to follow a redirect that did not meet the public-target policy.",
                            "Review the redirect destination and ensure it is an authorized public HTTPS target.",
                        )
                    )
                    checks["redirects"] = "inconclusive"
                    status = "partial"
                    error_message = "The redirect chain stopped because its destination failed the safety policy."
                    break
                redirect_observations.append({
                    "status": response.status_code,
                    "source": _display_url(current_url),
                    "destination": _display_url(next_url),
                })
                redirects.append(next_url)
                current_url = next_url
                continue
            break

        if response is not None:
            final_scheme = urlsplit(current_url).scheme
            cloudflare_challenge = response.headers.get("cf-mitigated", "").strip().lower() == "challenge"
            if response.status_code == 403 or cloudflare_challenge:
                challenge_evidence = (
                    "The final response returned HTTP 403. This may be an access policy or challenge response and is not assumed to represent the normal website response."
                    if response.status_code == 403
                    else f"The final response included the explicit cf-mitigated: challenge signal (HTTP {response.status_code}); it is not assumed to represent the normal website response."
                )
                findings.append(_finding(
                    "scan.access-restricted",
                    "Assessment response was access restricted",
                    "info",
                    "scan-limit",
                    challenge_evidence,
                    "Security header and cookie absence cannot be assessed reliably from an access-restricted response. No vulnerability is inferred from this status alone.",
                    "If authorized, arrange a permitted assessment path or review the relevant configuration through an owner-approved channel.",
                    confidence="high",
                ))
                checks["headers"] = "inconclusive"
                checks["cookies"] = "inconclusive" if final_scheme == "https" else "skipped"
                checks["transport"] = "completed"
                status = "partial"
                error_message = "The target returned an access-restricted or explicit challenge response; response-dependent security checks are inconclusive."
                check_details = {
                    "response_status": response.status_code,
                    "final_url": _display_url(current_url),
                    "dns_observations": dns_observations,
                    "tls_valid": response.tls_valid,
                    "tls_expires_at": response.tls_expires_at.isoformat() if response.tls_expires_at else None,
                    "redirect_observations": redirect_observations,
                    "rule_results": {"headers": "inconclusive", "cookies": "inconclusive"},
                    "scanner_version": 2,
                }
            else:
                findings.extend(self._analyze_response(normalized_url, current_url, response, redirects))
                checks["headers"] = "completed"
                checks["cookies"] = "completed" if final_scheme == "https" else "skipped"
                check_details = _safe_response_details(response, current_url, redirect_observations, final_scheme)
                check_details["dns_observations"] = dns_observations
                check_details["tls_valid"] = response.tls_valid
                check_details["tls_expires_at"] = response.tls_expires_at.isoformat() if response.tls_expires_at else None
        else:
            check_details = {"dns_observations": dns_observations, "redirect_observations": redirect_observations, "scanner_version": 2}
        findings = deduplicate_findings(findings)
        score, level = calculate_risk_score(finding.severity for finding in findings)
        return ScanReport(
            normalized_url=normalized_url,
            status=status,
            findings=findings,
            risk_score=score,
            risk_level=level,
            error_message=error_message,
            redirects=redirects,
            checks=checks,
            check_details=check_details,
        )

    @staticmethod
    def _analyze_response(
        original_url: str, final_url: str, response: FetchResponse, redirects: list[str]
    ) -> list[FindingResult]:
        findings: list[FindingResult] = []
        final_scheme = urlsplit(final_url).scheme
        if final_scheme != "https":
            findings.append(
                _finding(
                    "transport.https-not-enforced",
                    "Final response is not using HTTPS",
                    "medium",
                    "transport",
                    f"The final assessed URL remained {final_url}.",
                    "This confirms transport was not encrypted for the final response; it does not prove a data exposure occurred.",
                    "Serve the site over HTTPS and redirect HTTP requests to HTTPS.",
                )
            )
        elif response.tls_expires_at is not None and response.tls_expires_at <= datetime.now(UTC) + timedelta(days=30):
            findings.append(
                _finding(
                    "tls.certificate-expiring",
                    "HTTPS certificate expires within 30 days",
                    "medium",
                    "transport",
                    f"The certificate expiry is {response.tls_expires_at.isoformat()}.",
                    "The certificate is currently usable but its remaining validity is limited.",
                    "Renew the certificate before expiry and keep automated renewal monitoring in place.",
                )
            )

        findings.extend(
            finding
            for finding in (
                _header_finding(response, "strict-transport-security", "headers.hsts-missing", "Strict-Transport-Security header is missing", "Add HSTS after confirming all site resources and subdomains support HTTPS.") if final_scheme == "https" else None,
                _header_finding(response, "content-security-policy", "headers.csp-missing", "Content-Security-Policy header is missing", "Define a restrictive Content-Security-Policy appropriate for the application."),
                _header_finding(response, "x-content-type-options", "headers.content-type-options-missing", "X-Content-Type-Options header is missing", "Set X-Content-Type-Options: nosniff."),
                _header_finding(response, "referrer-policy", "headers.referrer-policy-missing", "Referrer-Policy header is missing", "Set an explicit Referrer-Policy appropriate for the application."),
                _header_finding(response, "x-frame-options", "headers.frame-options-missing", "X-Frame-Options header is missing", "Set X-Frame-Options or use frame-ancestors in Content-Security-Policy.") if not re.search(r"(?i)(?:^|;)\s*frame-ancestors\b", response.headers.get("content-security-policy", "")) else None,
                _header_finding(response, "permissions-policy", "headers.permissions-policy-missing", "Permissions-Policy header is missing", "Set an explicit Permissions-Policy for browser features that the application does not need."),
            )
            if finding is not None
        )
        hsts_value = response.headers.get("strict-transport-security", "").strip()
        if final_scheme == "https" and hsts_value and _header_rule_results(response, final_scheme).get("headers.hsts") == "invalid":
            findings.append(_finding(
                "headers.hsts-invalid", "Strict-Transport-Security header has no effective max-age",
                "low", "security-header", f"The HTTPS response included a Strict-Transport-Security value that did not contain a positive max-age: {hsts_value[:500]}",
                "Browsers ignore HSTS when the required max-age directive is absent or invalid; no HSTS policy is inferred from this value.",
                "Set a positive max-age after confirming HTTPS is consistently available. Add includeSubDomains or preload only after reviewing their broader impact.",
            ))
        content_type_options = response.headers.get("x-content-type-options", "").strip()
        if content_type_options and content_type_options.lower() != "nosniff":
            findings.append(_finding(
                "headers.content-type-options-invalid", "X-Content-Type-Options is not set to nosniff", "low", "security-header",
                f"The final response supplied X-Content-Type-Options: {content_type_options[:500]}.",
                "The observed value does not request the browser's nosniff behavior; impact depends on how responses are served and interpreted.",
                "Set X-Content-Type-Options: nosniff on responses with appropriate content types.",
            ))
        if final_scheme == "https":
            findings.extend(_cookie_findings(response))
        return findings
