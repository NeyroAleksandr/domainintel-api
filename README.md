# DomainIntel API

Full domain intelligence in **one API call**: DNS records, WHOIS (via official RDAP), technology stack, on-page SEO snapshot, SSL certificate, and IP network ownership.

```bash
curl https://YOUR-HOST/v1/report/example.com
```

```json
{
  "domain": "example.com",
  "sections_ok": 6,
  "dns":   { "ips": ["..."], "records": { "A": [], "MX": [], "NS": [], "TXT": [] } },
  "whois": { "registrar": "...", "created": "...", "expires": "...", "dnssec": false },
  "ssl":   { "issuer": "Let's Encrypt", "days_left": 62, "tls_version": "TLSv1.3" },
  "seo":   { "title": "...", "issues": ["missing meta description"], "response_ms": 734 },
  "tech":  { "cms": ["WordPress"], "technologies": ["jQuery", "Google Analytics"] },
  "ip":    { "organization": "...", "country": "...", "cidr": "..." }
}
```

## Why

- **One call instead of five services.** WHOIS + DNS + tech detection + SEO + SSL usually means five subscriptions.
- **No third-party API keys.** WHOIS comes from RDAP (the official registry protocol), DNS from DNS-over-HTTPS, everything else is measured directly. Nothing to sign up for.
- **Self-hostable.** MIT-licensed, two-file deploy with Docker.

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /v1/report/{domain}` | Everything below combined (sections run in parallel) |
| `GET /v1/dns/{domain}` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA, resolve, reverse DNS |
| `GET /v1/whois/{domain}` | Registrar, dates, status, nameservers, DNSSEC (RDAP) |
| `GET /v1/tech/{domain}` | CMS/platform + 20 tech signatures + security headers |
| `GET /v1/seo/{domain}` | Title/meta/H1/canonical, robots.txt, sitemap, issues list |
| `GET /v1/ssl/{domain}` | Issuer, expiry, days left, TLS version |
| `GET /v1/ip/{ip}` | Network owner, country, CIDR (RDAP) |
| `GET /v1/me` | Your key's usage and remaining quota |

Interactive docs at `/docs` (OpenAPI).

## Auth & limits

Pass `X-API-Key: <key>`. Without a key you get a demo quota (default 5 requests/day per IP).

Create keys (self-hosted):

```bash
curl -X POST http://localhost:8022/admin/keys \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label": "my-app", "daily_limit": 1000}'
```

## Self-host

```bash
git clone <this repo> && cd DomainIntel
cp .env.example .env   # set ADMIN_TOKEN
docker compose up -d --build
curl http://localhost:8022/v1/report/example.com
```

Or without Docker:

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
ADMIN_TOKEN=changeme .venv/bin/uvicorn app.main:app --port 8022
```

## Hosted version

Don't want to host it yourself? A managed instance is live at **https://api.direct-shablony.online** — try it right now, no signup:

```bash
curl https://api.direct-shablony.online/v1/report/example.com
```

Free demo: 5 requests/day. For an API key with higher limits, email **aa04193@gmail.com** — crypto and YooMoney accepted, no Western card required.

## License

MIT
