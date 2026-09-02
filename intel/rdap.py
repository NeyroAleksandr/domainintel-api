"""WHOIS data via RDAP — the official successor to WHOIS (RFC 7483).

rdap.org bootstraps to the authoritative registry. JSON, keyless, free.
"""

from __future__ import annotations

import httpx

RDAP_BASE = "https://rdap.org"


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


async def domain_rdap(domain: str, client: httpx.AsyncClient) -> dict:
    result: dict = {"domain": domain, "source": "rdap"}
    try:
        resp = await client.get(f"{RDAP_BASE}/domain/{domain}")
        if resp.status_code == 404:
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
