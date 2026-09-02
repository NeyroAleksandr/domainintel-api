"""DomainIntel API — one call, full domain intelligence.

Endpoints:
    GET  /v1/report/{domain}   full report (DNS + WHOIS + tech + SEO + SSL + IP)
    GET  /v1/dns/{domain}      DNS records + resolve + reverse
    GET  /v1/whois/{domain}    RDAP registration data
    GET  /v1/tech/{domain}     CMS / technology detection
    GET  /v1/seo/{domain}      on-page SEO snapshot
    GET  /v1/ssl/{domain}      TLS certificate info
    GET  /v1/ip/{ip}           network ownership (RDAP)
    GET  /v1/me                API key usage stats
    POST /admin/keys           create API key (admin token required)

Auth: X-API-Key header. Without a key: demo quota per client IP per day.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import date

from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app import db
from intel import dns_tools, rdap, seo, ssl_info, tech
from intel.http import DEFAULT_TIMEOUT, fetch_page
from intel.report import InvalidDomainError, full_report, normalize_domain

DEMO_DAILY = int(os.getenv("DEMO_DAILY", "5"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"

_demo_usage: dict[tuple[str, str], int] = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="DomainIntel API",
    version="1.0.0",
    description="Domain intelligence in one call: DNS, WHOIS (RDAP), tech stack, SEO, SSL.",
    lifespan=lifespan,
)


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def require_access(
    request: Request, x_api_key: str | None = Header(default=None)
) -> str:
    if x_api_key:
        ok, reason = db.check_and_count(x_api_key)
        if not ok:
            raise HTTPException(status_code=429 if "limit" in reason else 401, detail=reason)
        return x_api_key

    ip_key = (_client_ip(request), date.today().isoformat())
    used = _demo_usage.get(ip_key, 0)
    if used >= DEMO_DAILY:
        raise HTTPException(
            status_code=429,
            detail=f"demo limit reached ({DEMO_DAILY}/day). Get an API key for more.",
        )
    _demo_usage[ip_key] = used + 1
    return "demo"


def _domain_or_400(raw: str) -> str:
    try:
        return normalize_domain(raw)
    except InvalidDomainError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api")
async def api_info() -> dict:
    return {
        "service": "DomainIntel API",
        "docs": "/docs",
        "report": "/v1/report/{domain}",
        "demo": f"{DEMO_DAILY} requests/day without a key",
    }


@app.get("/v1/report/{domain}")
async def report(domain: str, _: str = Depends(require_access)) -> dict:
    return await full_report(_domain_or_400(domain))


@app.get("/v1/dns/{domain}")
async def dns_endpoint(domain: str, _: str = Depends(require_access)) -> dict:
    dom = _domain_or_400(domain)
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        return await dns_tools.dns_report(dom, client)


@app.get("/v1/whois/{domain}")
async def whois_endpoint(domain: str, _: str = Depends(require_access)) -> dict:
    dom = _domain_or_400(domain)
    async with httpx.AsyncClient(follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        return await rdap.domain_rdap(dom, client)


@app.get("/v1/tech/{domain}")
async def tech_endpoint(domain: str, _: str = Depends(require_access)) -> dict:
    dom = _domain_or_400(domain)
    page = await fetch_page(dom)
    return tech.detect(page)


@app.get("/v1/seo/{domain}")
async def seo_endpoint(domain: str, _: str = Depends(require_access)) -> dict:
    dom = _domain_or_400(domain)
    async with httpx.AsyncClient(follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        page = await fetch_page(dom, client)
        return await seo.analyze(page, client)


@app.get("/v1/ssl/{domain}")
async def ssl_endpoint(domain: str, _: str = Depends(require_access)) -> dict:
    return await ssl_info.cert_info(_domain_or_400(domain))


@app.get("/v1/ip/{ip}")
async def ip_endpoint(ip: str, _: str = Depends(require_access)) -> dict:
    async with httpx.AsyncClient(follow_redirects=True, timeout=DEFAULT_TIMEOUT) as client:
        return await rdap.ip_rdap(ip, client)


@app.get("/v1/me")
async def me(x_api_key: str | None = Header(default=None)) -> dict:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    stats = db.key_stats(x_api_key)
    if stats is None:
        raise HTTPException(status_code=401, detail="invalid API key")
    return stats


class KeyRequest(BaseModel):
    label: str = Field(min_length=1, max_length=100)
    daily_limit: int = Field(default=100, ge=1, le=100_000)


@app.post("/admin/keys")
async def create_key(
    body: KeyRequest, x_admin_token: str | None = Header(default=None)
) -> dict:
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin token required")
    key = db.create_key(body.label, body.daily_limit)
    return {"key": key, "label": body.label, "daily_limit": body.daily_limit}
