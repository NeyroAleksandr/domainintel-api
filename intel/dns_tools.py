"""DNS via Google DNS-over-HTTPS + reverse DNS via stdlib."""

from __future__ import annotations

import asyncio
import socket

import httpx

DOH_URL = "https://dns.google/resolve"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")


async def _query(client: httpx.AsyncClient, domain: str, rtype: str) -> tuple[str, list[str]]:
    try:
        resp = await client.get(
            DOH_URL,
            params={"name": domain, "type": rtype},
            headers={"Accept": "application/dns-json"},
        )
        resp.raise_for_status()
        answers = resp.json().get("Answer", [])
        return rtype, [a.get("data", "") for a in answers if a.get("data")]
    except (httpx.HTTPError, ValueError):
        return rtype, []


async def get_records(domain: str, client: httpx.AsyncClient) -> dict[str, list[str]]:
    """All record types in parallel over one connection."""
    pairs = await asyncio.gather(*[_query(client, domain, rt) for rt in RECORD_TYPES])
    return {rtype: values for rtype, values in pairs if values}


def resolve_sync(domain: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def reverse_dns_sync(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


async def dns_report(domain: str, client: httpx.AsyncClient) -> dict:
    records_task = get_records(domain, client)
    ips_task = asyncio.to_thread(resolve_sync, domain)
    records, ips = await asyncio.gather(records_task, ips_task)

    primary_ip = ips[0] if ips else None
    reverse = await asyncio.to_thread(reverse_dns_sync, primary_ip) if primary_ip else None

    return {
        "domain": domain,
        "ips": ips,
        "primary_ip": primary_ip,
        "reverse_dns": reverse,
        "records": records,
    }
