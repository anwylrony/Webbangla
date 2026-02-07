from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any, Dict

from .validation import Target, validate_target
from .dns_checks import gather_dns
from .http_checks import gather_http_info, gather_security_headers, gather_waf_signals
from .tls_checks import gather_tls_info
from .tech_fingerprint import fingerprint_tech
from .findings import build_findings


def run_scan(target: str, safe_mode: bool = True) -> Dict[str, Any]:
    start = time.time()
    validated = validate_target(target)

    dns_info = gather_dns(validated)
    http_info = gather_http_info(validated, safe_mode=safe_mode)
    tls_info = gather_tls_info(validated)
    tech_info = fingerprint_tech(http_info)
    headers_info = gather_security_headers(http_info)
    waf_info = gather_waf_signals(http_info)

    findings = build_findings(
        target=validated,
        dns_info=dns_info,
        http_info=http_info,
        tls_info=tls_info,
        tech_info=tech_info,
        headers_info=headers_info,
        waf_info=waf_info,
    )

    duration = round(time.time() - start, 2)

    return {
        "metadata": {
            "target": asdict(validated),
            "safe_mode": safe_mode,
            "scan_duration_seconds": duration,
        },
        "target_validation": asdict(validated),
        "dns": dns_info,
        "http": http_info,
        "tls": tls_info,
        "technology": tech_info,
        "headers": headers_info,
        "waf": waf_info,
        "findings": findings,
        "manual_guidance": {
            "business_logic": [
                "Validate each workflow step cannot be skipped using direct endpoint calls.",
                "Attempt to replay payment or order requests with modified amounts.",
                "Test coupon endpoints for reuse, stacking, and unauthorized application.",
                "Manipulate hidden fields and observe server-side validation.",
                "Test state transitions (e.g., order cancel after shipment) for bypass.",
            ],
        },
    }
