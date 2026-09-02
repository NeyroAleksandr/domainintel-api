"""Full domain report — all sections in parallel, per-section error capture."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Awaitable

import httpx

from intel import dns_tools, rdap, seo, ssl_info, tech
from intel.http import DEFAULT_TIMEOUT, fetch_page

DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class InvalidDomainError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Accept bare domain or URL; return punycoded hostname."""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0].split("?")[0].split(":")[0]
    if value.startswith("www."):
        value = value[4:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise InvalidDomainError(f"cannot encode domain: {raw!r}") from e
    if not DOMAIN_RE.match(value):
        raise InvalidDomainError(f"not a valid domain: {raw!r}")
    return value


async def _section(name: str, coro: Awaitable[dict]) -> tuple[str, dict]:
    try:
        return name, await coro
    except Exception as e:  # noqa: BLE001 — section failure must not kill the report
        return name, {"error": f"{type(e).__name__}: {e}"}


async def full_report(raw_domain: str) -> dict[str, Any]:
    domain = normalize_domain(raw_domain)

    async with httpx.AsyncClient(follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        page_task = asyncio.create_task(fetch_page(domain, client))
        dns_pair, whois_pair, ssl_pair, page = await asyncio.gather(
            _section("dns", dns_tools.dns_report(domain, client)),
            _section("whois", rdap.domain_rdap(domain, client)),
            _section("ssl", ssl_info.cert_info(domain)),
            page_task,
        )

        seo_pair = await _section("seo", seo.analyze(page, client))
        tech_result = tech.detect(page)

        sections = dict([dns_pair, whois_pair, ssl_pair, seo_pair])
        sections["tech"] = tech_result

        primary_ip = sections["dns"].get("primary_ip")
        if primary_ip:
            _, ip_result = await _section("ip", rdap.ip_rdap(primary_ip, client))
            sections["ip"] = ip_result
        else:
            sections["ip"] = {"error": "domain does not resolve"}

    ok = sum(1 for s in sections.values() if not s.get("error"))
    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sections_ok": ok,
        "sections_total": len(sections),
        **sections,
    }
