"""On-page SEO snapshot: meta, headings, robots.txt, sitemap, canonical."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from intel.http import UA, PageData


def _text(pattern: str, html: str) -> str | None:
    m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip() or None


async def _exists(client: httpx.AsyncClient, url: str) -> bool:
    try:
        resp = await client.get(url, headers={"User-Agent": UA})
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


async def analyze(page: PageData, client: httpx.AsyncClient) -> dict:
    result: dict = {"url": page.url, "error": page.error}
    if page.error:
        return result

    html = page.html
    parsed = urlparse(page.final_url or page.url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    robots_ok, sitemap_ok = await asyncio.gather(
        _exists(client, f"{root}/robots.txt"),
        _exists(client, f"{root}/sitemap.xml"),
    )

    title = _text(r"<title[^>]*>(.*?)</title>", html)
    description = _text(
        r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html
    ) or _text(r'<meta\s+content=["\'](.*?)["\']\s+name=["\']description["\']', html)

    h1s = re.findall(r"<h1[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
    canonical = _text(r'<link\s+rel=["\']canonical["\']\s+href=["\'](.*?)["\']', html)

    issues: list[str] = []
    if not title:
        issues.append("missing <title>")
    elif len(title) > 60:
        issues.append(f"title too long ({len(title)} chars, max ~60)")
    if not description:
        issues.append("missing meta description")
    elif len(description) > 160:
        issues.append(f"meta description too long ({len(description)} chars, max ~160)")
    if not h1s:
        issues.append("no <h1> on page")
    elif len(h1s) > 1:
        issues.append(f"multiple <h1> tags ({len(h1s)})")
    if not canonical:
        issues.append("no canonical link")
    if not robots_ok:
        issues.append("robots.txt missing")
    if not sitemap_ok:
        issues.append("sitemap.xml missing")
    if not (page.final_url or "").startswith("https://"):
        issues.append("not served over HTTPS")
    if page.elapsed_ms > 3000:
        issues.append(f"slow response ({page.elapsed_ms} ms)")
    if page.size_bytes > 3_000_000:
        issues.append(f"heavy page ({page.size_bytes // 1024} KB)")

    result.update(
        {
            "status": page.status,
            "final_url": page.final_url,
            "https": (page.final_url or "").startswith("https://"),
            "response_ms": page.elapsed_ms,
            "page_size_bytes": page.size_bytes,
            "title": title,
            "title_length": len(title) if title else 0,
            "meta_description": description,
            "h1_count": len(h1s),
            "canonical": canonical,
            "robots_txt": robots_ok,
            "sitemap_xml": sitemap_ok,
            "issues": issues,
            "issues_count": len(issues),
        }
    )
    return result
