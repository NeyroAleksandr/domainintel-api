"""Shared HTTP fetch layer. One page fetch feeds tech + SEO analyzers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 DomainIntel/1.0"

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)


@dataclass
class PageData:
    url: str
    final_url: str = ""
    status: int = 0
    html: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    size_bytes: int = 0
    error: str | None = None


async def fetch_page(url: str, client: httpx.AsyncClient | None = None) -> PageData:
    """Fetch a page once; analyzers reuse the result."""
    if not url.startswith("http"):
        url = f"https://{url}"
    page = PageData(url=url)
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(follow_redirects=True, timeout=DEFAULT_TIMEOUT)
    try:
        t0 = time.monotonic()
        resp = await client.get(url, headers={"User-Agent": UA})
        page.elapsed_ms = int((time.monotonic() - t0) * 1000)
        page.status = resp.status_code
        page.final_url = str(resp.url)
        page.html = resp.text or ""
        page.headers = {k.lower(): v for k, v in resp.headers.items()}
        page.size_bytes = len(resp.content or b"")
    except httpx.HTTPError as e:
        page.error = f"{type(e).__name__}: {e}"
    finally:
        if own_client:
            await client.aclose()
    return page
