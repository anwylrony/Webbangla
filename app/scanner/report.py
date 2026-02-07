from __future__ import annotations

from typing import Any, Dict


def build_report(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    findings = scan_result.get("findings", [])
    summary_table = [
        {
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "affected_endpoint": finding.get("affected_endpoint"),
        }
        for finding in findings
    ]

    risk_overview = {
        "critical": len([f for f in findings if f.get("severity") == "Critical"]),
        "high": len([f for f in findings if f.get("severity") == "High"]),
        "medium": len([f for f in findings if f.get("severity") == "Medium"]),
        "low": len([f for f in findings if f.get("severity") == "Low"]),
        "informational": len([f for f in findings if f.get("severity") == "Informational"]),
    }

    return {
        "executive_summary": {
            "statement": "This assessment summarizes passive and safe validation checks performed against the provided target.",
            "limitations": [
                "Active exploitation and intrusive testing are intentionally excluded.",
                "Some checks rely on public data sources and may be incomplete.",
            ],
        },
        "scope_and_methodology": {
            "target": scan_result.get("target_validation"),
            "methods": [
                "Passive DNS and HTTP analysis",
                "TLS configuration review",
                "Header and technology fingerprinting",
                "Safe exposure checks",
            ],
        },
        "summary_table": summary_table,
        "detailed_findings": findings,
        "risk_overview": risk_overview,
        "remediation_roadmap": [
            "Prioritize high and medium findings for remediation within 30 days.",
            "Re-test after fixes to validate closure and assess residual risk.",
            "Maintain a continuous monitoring program for TLS and header hardening.",
        ],
        "raw_sections": {
            "target_validation": scan_result.get("target_validation"),
            "dns": scan_result.get("dns"),
            "http": scan_result.get("http"),
            "tls": scan_result.get("tls"),
            "technology": scan_result.get("technology"),
            "headers": scan_result.get("headers"),
            "waf": scan_result.get("waf"),
            "manual_guidance": scan_result.get("manual_guidance"),
        },
    }
