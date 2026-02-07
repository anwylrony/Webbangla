from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import ipaddress


@dataclass
class Target:
    input: str
    target_type: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[str] = None
    scheme: Optional[str] = None
    web_entrypoints: Optional[list[str]] = None


def validate_target(target: str) -> Target:
    target = target.strip()

    parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
    hostname = parsed.hostname
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"

    try:
        ip_obj = ipaddress.ip_address(target)
        return Target(
            input=target,
            target_type="ip",
            ip=str(ip_obj),
            scheme=scheme,
            web_entrypoints=[f"{scheme}://{ip_obj}", f"http://{ip_obj}", f"https://{ip_obj}"],
        )
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(target, strict=False)
        return Target(
            input=target,
            target_type="cidr",
            cidr=str(network),
        )
    except ValueError:
        pass

    if hostname:
        return Target(
            input=target,
            target_type="domain",
            hostname=hostname,
            scheme=scheme,
            web_entrypoints=[
                f"{scheme}://{hostname}",
                f"http://{hostname}",
                f"https://{hostname}",
            ],
        )

    raise ValueError("Unsupported target format. Use a domain, URL, IP, or CIDR.")
