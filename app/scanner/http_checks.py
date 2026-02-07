from __future__ import annotations

from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup

from .validation import Target

REQUEST_TIMEOUT = 10


class HttpInfo:
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        title: str,
        cookies: Dict[str, str],
        body_snippet: str,
        set_cookie: str | None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.title = title
        self.cookies = cookies
        self.body_snippet = body_snippet
        self.set_cookie = set_cookie


WAF_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server"],
    "akamai": ["akamai", "ak-pipeline"],
    "imperva": ["x-cdn", "incap_ses"],
    "aws_waf": ["x-amzn-requestid", "x-amzn-trace-id"],
    "fastly": ["fastly", "x-served-by"],
}


def _fetch(url: str) -> HttpInfo:
    response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    soup = BeautifulSoup(response.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    headers = {k.lower(): v for k, v in response.headers.items()}
    return HttpInfo(
        url=response.url,
        status_code=response.status_code,
        headers=headers,
        title=title,
        cookies=response.cookies.get_dict(),
        body_snippet=response.text[:500],
        set_cookie=headers.get("set-cookie"),
    )


def gather_http_info(target: Target, safe_mode: bool = True) -> Dict[str, Any]:
    if not target.web_entrypoints:
        return {"note": "HTTP discovery is only available for web targets."}

    urls = list(dict.fromkeys(target.web_entrypoints))
    results: List[Dict[str, Any]] = []

    for url in urls:
        try:
            info = _fetch(url)
            results.append(
                {
                    "url": info.url,
                    "status_code": info.status_code,
                    "title": info.title,
                    "headers": info.headers,
                    "set_cookie": info.set_cookie,
                    "cookies": info.cookies,
                    "body_snippet": info.body_snippet,
                }
            )
        except requests.RequestException as exc:
            results.append({"url": url, "error": str(exc)})

    primary = results[0] if results else {}

    directory_listing = False
    if primary.get("body_snippet"):
        snippet_lower = primary["body_snippet"].lower()
        directory_listing = "index of /" in snippet_lower and "parent directory" in snippet_lower

    exposure_checks = []
    if safe_mode:
        exposure_checks.append(
            {
                "check": "Directory listing",
                "observed": directory_listing,
                "details": "Detected common directory listing markers on the root page.",
            }
        )

    return {
        "entries": results,
        "primary": primary,
        "safe_mode": safe_mode,
        "exposure_checks": exposure_checks,
    }


def gather_security_headers(http_info: Dict[str, Any]) -> Dict[str, Any]:
    primary_headers = http_info.get("primary", {}).get("headers", {})
    security_headers = {
        "content-security-policy": primary_headers.get("content-security-policy"),
        "x-frame-options": primary_headers.get("x-frame-options"),
        "x-content-type-options": primary_headers.get("x-content-type-options"),
        "referrer-policy": primary_headers.get("referrer-policy"),
        "permissions-policy": primary_headers.get("permissions-policy"),
        "strict-transport-security": primary_headers.get("strict-transport-security"),
    }
    missing = [key for key, value in security_headers.items() if not value]
    return {"observed": security_headers, "missing": missing}


def gather_waf_signals(http_info: Dict[str, Any]) -> Dict[str, Any]:
    headers = http_info.get("primary", {}).get("headers", {})
    lower_headers = {k.lower(): v for k, v in headers.items()}

    detected = []
    for waf_name, signals in WAF_HEADER_SIGNATURES.items():
        if any(signal in lower_headers for signal in signals):
            detected.append(waf_name)

    return {
        "detected": detected,
        "evidence": lower_headers,
    }
