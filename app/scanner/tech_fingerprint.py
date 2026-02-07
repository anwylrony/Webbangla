from __future__ import annotations

from typing import Any, Dict, List


def fingerprint_tech(http_info: Dict[str, Any]) -> Dict[str, Any]:
    primary = http_info.get("primary", {})
    headers = primary.get("headers", {})
    body = primary.get("body_snippet", "")

    server = headers.get("server")
    framework = headers.get("x-powered-by")

    cms = []
    body_lower = body.lower()
    if "wp-content" in body_lower or "wordpress" in body_lower:
        cms.append("WordPress")
    if "drupal" in body_lower:
        cms.append("Drupal")
    if "joomla" in body_lower:
        cms.append("Joomla")

    libraries = []
    if "jquery" in body_lower:
        libraries.append("jQuery")
    if "bootstrap" in body_lower:
        libraries.append("Bootstrap")

    return {
        "web_server": server,
        "framework": framework,
        "cms": cms,
        "libraries": libraries,
    }
