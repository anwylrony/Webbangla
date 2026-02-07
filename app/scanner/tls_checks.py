from __future__ import annotations

from datetime import datetime
import socket
import ssl
from typing import Any, Dict

from .validation import Target


TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _probe_tls_version(hostname: str, version: ssl.TLSVersion) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except (ssl.SSLError, socket.error, socket.timeout):
        return False


def gather_tls_info(target: Target) -> Dict[str, Any]:
    hostname = target.hostname or target.ip
    if not hostname:
        return {"note": "TLS checks require a hostname or IP target."}

    tls_support = {name: _probe_tls_version(hostname, version) for name, version in TLS_VERSIONS.items()}

    cert_info: Dict[str, Any] = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
                if cert.get("notAfter"):
                    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    cert_info["days_until_expiry"] = (expires - datetime.utcnow()).days
    except (ssl.SSLError, socket.error, socket.timeout, ValueError) as exc:
        cert_info = {"error": str(exc)}

    weak_protocols = [name for name, supported in tls_support.items() if supported and name in {"TLSv1", "TLSv1.1"}]

    return {
        "supported_protocols": tls_support,
        "weak_protocols": weak_protocols,
        "certificate": cert_info,
    }
