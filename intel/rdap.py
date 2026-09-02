"""WHOIS data via RDAP — the official successor to WHOIS (RFC 7483).

rdap.org bootstraps to the authoritative registry. JSON, keyless, free.
TLDs without public RDAP (.ru/.su/.рф) fall back to classic whois on port 43.
"""

from __future__ import annotations

import asyncio
import socket

import httpx

RDAP_BASE = "https://rdap.org"

WHOIS43_SERVERS = {
    "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
    "xn--p1ai": "whois.tcinet.ru",  # .рф
}

_WHOIS43_FIELDS = {
    "registrar": "registrar",
    "created": "created",
    "paid-till": "expires",
    "org": "registrant",
}


def _parse_events(events: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    mapping = {
        "registration": "created",
        "expiration": "expires",
        "last changed": "updated",
        "last update of RDAP database": "rdap_updated",
    }
    for ev in events or []:
        key = mapping.get(ev.get("eventAction", ""))
        if key and ev.get("eventDate"):
            out[key] = ev["eventDate"]
    return out


def _parse_entities(entities: list[dict]) -> dict[str, str]:
    """Pull registrar / registrant names out of vCard entities."""
    out: dict[str, str] = {}
    for ent in entities or []:
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [])
        name = None
        if len(vcard) == 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    name = item[3]
                    break
        if name:
            if "registrar" in roles:
                out["registrar"] = name
            elif "registrant" in roles:
                out["registrant"] = name
        if "registrar" not in out and "registrar" in roles and ent.get("handle"):
            out["registrar"] = ent["handle"]
    return out


def _whois43_query(domain: str, server: str, timeout: float = 12.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{domain}\r\n".encode())
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="ignore")


def _parse_whois43(domain: str, raw: str) -> dict:
    result: dict = {"domain": domain, "source": "whois43"}
    status: list[str] = []
    nameservers: list[str] = []
    for line in raw.splitlines():
        if ":" not in line or line.lstrip().startswith("%"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key == "state":
            status = [s.strip() for s in value.split(",")]
        elif key == "nserver":
            nameservers.append(value.rstrip(".").lower())
        elif key in _WHOIS43_FIELDS and _WHOIS43_FIELDS[key] not in result:
            result[_WHOIS43_FIELDS[key]] = value
    if status:
        result["status"] = status
    if nameservers:
        result["nameservers"] = nameservers
    if "No entries found" in raw:
        result["error"] = "domain is not registered"
    return result


async def _whois43_fallback(domain: str) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    server = WHOIS43_SERVERS.get(tld)
    if not server:
        return None
    try:
        raw = await asyncio.to_thread(_whois43_query, domain, server)
    except OSError as e:
        return {"domain": domain, "source": "whois43", "error": f"{type(e).__name__}: {e}"}
    return _parse_whois43(domain, raw)


async def domain_rdap(domain: str, client: httpx.AsyncClient) -> dict:
    result: dict = {"domain": domain, "source": "rdap"}
    try:
        resp = await client.get(f"{RDAP_BASE}/domain/{domain}")
        if resp.status_code == 404:
            fallback = await _whois43_fallback(domain)
            if fallback is not None:
                return fallback
            result["error"] = "domain not found in RDAP (unregistered or unsupported TLD)"
            return result
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    result.update(_parse_events(data.get("events", [])))
    result.update(_parse_entities(data.get("entities", [])))
    result["status"] = data.get("status", [])
    result["nameservers"] = [
        ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")
    ]
    dnssec = data.get("secureDNS", {})
    result["dnssec"] = bool(dnssec.get("delegationSigned"))
    return result


async def ip_rdap(ip: str, client: httpx.AsyncClient) -> dict:
    """Network ownership: org, country, AS range — official registry data."""
    result: dict = {"ip": ip, "source": "rdap"}
    try:
        resp = await client.get(f"{RDAP_BASE}/ip/{ip}")
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    result["network_name"] = data.get("name")
    result["country"] = data.get("country")
    result["cidr"] = (
        f"{data.get('startAddress', '')} - {data.get('endAddress', '')}"
        if data.get("startAddress")
        else None
    )
    ent_info = _parse_entities(data.get("entities", []))
    org = ent_info.get("registrant") or ent_info.get("registrar")
    if not org:
        for ent in data.get("entities", []):
            vcard = ent.get("vcardArray", [])
            if len(vcard) == 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and item[3]:
                        org = item[3]
                        break
            if org:
                break
    result["organization"] = org
    return result
