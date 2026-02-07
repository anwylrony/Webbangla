from __future__ import annotations

from typing import Any, Dict, List

import dns.resolver

from .validation import Target


def _query_records(hostname: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, record_type, raise_on_no_answer=False)
    except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []

    if not answers:
        return []

    return [str(rdata).strip() for rdata in answers]


def gather_dns(target: Target) -> Dict[str, Any]:
    if not target.hostname:
        return {"note": "DNS lookup is only available for domain targets."}

    records = {
        "A": _query_records(target.hostname, "A"),
        "AAAA": _query_records(target.hostname, "AAAA"),
        "MX": _query_records(target.hostname, "MX"),
        "TXT": _query_records(target.hostname, "TXT"),
        "NS": _query_records(target.hostname, "NS"),
    }

    spf = [txt for txt in records["TXT"] if "v=spf1" in txt.lower()]
    dmarc = _query_records(f"_dmarc.{target.hostname}", "TXT")

    dkim_selectors = ["default", "selector1", "selector2", "google"]
    dkim_records = {
        selector: _query_records(f"{selector}._domainkey.{target.hostname}", "TXT")
        for selector in dkim_selectors
    }

    return {
        "records": records,
        "spf": spf or ["Not detected"],
        "dmarc": dmarc or ["Not detected"],
        "dkim": dkim_records,
    }
