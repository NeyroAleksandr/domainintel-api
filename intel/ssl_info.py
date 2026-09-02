"""TLS certificate inspection via stdlib ssl."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _fetch_cert(domain: str, timeout: float = 10.0) -> dict:
    result: dict = {"domain": domain}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result["tls_version"] = tls.version()
    except (OSError, ssl.SSLError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    if not cert:
        result["error"] = "no certificate returned"
        return result

    issuer = {k: v for pair in cert.get("issuer", []) for k, v in pair}
    subject = {k: v for pair in cert.get("subject", []) for k, v in pair}
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    result["subject"] = subject.get("commonName")
    result["san_count"] = len(cert.get("subjectAltName", []))

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, CERT_DATE_FMT).replace(tzinfo=timezone.utc)
            result["expires"] = expires.isoformat()
            result["days_left"] = (expires - datetime.now(timezone.utc)).days
        except ValueError:
            result["expires"] = not_after
    return result


async def cert_info(domain: str) -> dict:
    return await asyncio.to_thread(_fetch_cert, domain)
