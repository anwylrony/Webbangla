from __future__ import annotations

from typing import Any, Dict, List

from .validation import Target


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _build_finding(
    title: str,
    severity: str,
    endpoint: str,
    description: str,
    reproduction: str,
    evidence: str,
    impact: str,
    cvss: str,
    remediation: str,
) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "affected_endpoint": endpoint,
        "description": description,
        "reproduction_steps": reproduction,
        "proof_of_concept": evidence,
        "impact": impact,
        "cvss_v3_1": cvss,
        "remediation": remediation,
    }


def build_findings(
    target: Target,
    dns_info: Dict[str, Any],
    http_info: Dict[str, Any],
    tls_info: Dict[str, Any],
    tech_info: Dict[str, Any],
    headers_info: Dict[str, Any],
    waf_info: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    primary = http_info.get("primary", {})
    endpoint = primary.get("url") or target.input

    missing_headers = headers_info.get("missing", [])
    if missing_headers:
        findings.append(
            _build_finding(
                title="Missing security headers",
                severity="Low",
                endpoint=endpoint,
                description="One or more recommended HTTP security headers are absent.",
                reproduction="Send a GET request to the primary endpoint and inspect response headers.",
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                impact="Browser protections may be reduced, increasing risk of clickjacking or content injection.",
                cvss="3.7",
                remediation="Add the missing headers with recommended values and test using a security header scanner.",
            )
        )

    weak_protocols = tls_info.get("weak_protocols", [])
    if weak_protocols:
        findings.append(
            _build_finding(
                title="Weak TLS protocols enabled",
                severity="Medium",
                endpoint=endpoint,
                description="Legacy TLS versions are accepted by the server.",
                reproduction="Attempt TLS handshakes with TLSv1/TLSv1.1 and observe successful negotiation.",
                evidence=f"Supported weak protocols: {', '.join(weak_protocols)}",
                impact="Attackers may exploit known weaknesses in legacy TLS versions.",
                cvss="5.9",
                remediation="Disable TLSv1.0 and TLSv1.1 in server configuration, enforcing TLSv1.2+.",
            )
        )

    exposure_checks = http_info.get("exposure_checks", [])
    for check in exposure_checks:
        if check.get("check") == "Directory listing" and check.get("observed"):
            findings.append(
                _build_finding(
                    title="Directory listing enabled",
                    severity="Low",
                    endpoint=endpoint,
                    description="A directory listing appears to be enabled on the root path.",
                    reproduction="Browse to the root URL and verify the index listing of files.",
                    evidence="Index listing markers found in response body.",
                    impact="Attackers could enumerate files and sensitive assets.",
                    cvss="3.1",
                    remediation="Disable directory listing or add an index file to prevent listings.",
                )
            )

    set_cookie = primary.get("set_cookie") or ""
    if set_cookie and ("secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower()):
        findings.append(
            _build_finding(
                title="Session cookie missing Secure/HttpOnly flags",
                severity="Medium",
                endpoint=endpoint,
                description="Set-Cookie header lacks recommended flags for session cookies.",
                reproduction="Inspect the Set-Cookie header in the HTTP response.",
                evidence=f"Observed Set-Cookie: {set_cookie}",
                impact="Cookies may be exposed to client-side scripts or transmitted over insecure channels.",
                cvss="5.4",
                remediation="Set Secure, HttpOnly, and SameSite attributes for session cookies.",
            )
        )

    if waf_info.get("detected"):
        findings.append(
            _build_finding(
                title="WAF detected",
                severity="Informational",
                endpoint=endpoint,
                description="Response headers indicate a Web Application Firewall or CDN protection layer.",
                reproduction="Inspect response headers for WAF-specific markers.",
                evidence=f"Detected signals: {', '.join(waf_info.get('detected', []))}",
                impact="WAF presence is helpful, but it is not a substitute for secure development.",
                cvss="0.0",
                remediation="Maintain WAF rules and ensure they complement secure coding practices.",
            )
        )

    return findings
