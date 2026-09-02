"""Technology / CMS detection by signatures. Ported from SerpAPI_Kit cms_detector."""

from __future__ import annotations

import re

from intel.http import PageData

SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "WordPress": [
        (r"/wp-content/", "html"),
        (r"/wp-includes/", "html"),
        (r'<meta name="generator" content="WordPress', "html"),
        (r"wp-json", "html"),
    ],
    "Joomla": [
        (r"/media/jui/", "html"),
        (r'<meta name="generator" content="Joomla', "html"),
    ],
    "Drupal": [
        (r"Drupal\.settings", "html"),
        (r"/sites/default/files", "html"),
        (r'<meta name="Generator" content="Drupal', "html"),
    ],
    "1C-Bitrix": [
        (r"/bitrix/", "html"),
        (r"BX\.message", "html"),
        (r"bitrix_sessid", "html"),
    ],
    "Tilda": [
        (r"tildacdn\.com", "html"),
        (r"t-records", "html"),
        (r"tilda-animation", "html"),
    ],
    "Wix": [
        (r"wix\.com", "html"),
        (r"wixstatic\.com", "html"),
        (r"x-wix-", "headers"),
    ],
    "Squarespace": [
        (r"squarespace\.com", "html"),
        (r"squarespace-cdn", "html"),
    ],
    "Shopify": [
        (r"cdn\.shopify\.com", "html"),
        (r"Shopify\.theme", "html"),
        (r"myshopify\.com", "html"),
    ],
    "Next.js": [
        (r"__NEXT_DATA__", "html"),
        (r"/_next/static", "html"),
    ],
    "Nuxt.js": [
        (r"__NUXT__", "html"),
        (r"/_nuxt/", "html"),
    ],
    "React": [
        (r"__REACT_DEVTOOLS", "html"),
        (r'data-reactroot', "html"),
    ],
    "Vue.js": [
        (r"__vue__", "html"),
        (r"v-cloak", "html"),
    ],
    "Laravel": [
        (r"laravel_session", "headers"),
        (r"xsrf-token", "headers"),
    ],
    "Django": [
        (r"csrfmiddlewaretoken", "html"),
    ],
    "Flask": [
        (r"werkzeug", "headers"),
    ],
    "nginx": [(r"nginx", "server")],
    "Apache": [(r"apache", "server")],
    "Cloudflare": [
        (r"cloudflare", "server"),
        (r"cf-ray", "headers"),
    ],
    "OpenResty": [(r"openresty", "server")],
    "LiteSpeed": [(r"litespeed", "server")],
}

TECH_PATTERNS: dict[str, str] = {
    "jQuery": r"jquery[.\-]?\d*\.?(min\.)?js",
    "Bootstrap": r"bootstrap[.\-]?\d*\.?(min\.)?(css|js)",
    "Google Analytics": r"google-analytics\.com|gtag\(|UA-\d{4,}",
    "Google Tag Manager": r"googletagmanager\.com|GTM-",
    "Yandex.Metrika": r"mc\.yandex\.ru|ym\(\d+",
    "Facebook Pixel": r"connect\.facebook\.net|fbq\(",
    "reCAPTCHA": r"google\.com/recaptcha",
    "hCaptcha": r"hcaptcha\.com",
    "Cloudflare Turnstile": r"challenges\.cloudflare\.com/turnstile",
    "Stripe": r"js\.stripe\.com",
    "PayPal": r"paypal\.com/sdk",
    "Hotjar": r"hotjar\.com",
    "Intercom": r"intercom\.io|intercomcdn",
    "Crisp": r"crisp\.chat",
    "Tawk.to": r"tawk\.to",
    "Sentry": r"sentry\.io|browser\.sentry-cdn",
    "Font Awesome": r"font-?awesome",
    "Google Fonts": r"fonts\.googleapis\.com",
    "Tailwind CSS": r"tailwindcss|tailwind\.css",
    "AMP": r"cdn\.ampproject\.org",
    "PWA manifest": r'rel=["\']manifest["\']',
}

SECURITY_HEADERS = (
    "x-frame-options",
    "content-security-policy",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
)


def detect(page: PageData) -> dict:
    """Detect CMS/platform and technologies from an already-fetched page."""
    result: dict = {
        "url": page.url,
        "cms": [],
        "technologies": [],
        "server": None,
        "meta_generator": None,
        "security_headers": {},
        "error": page.error,
    }
    if page.error:
        return result

    server = page.headers.get("server", "")
    result["server"] = server or None

    headers_blob = "\n".join(f"{k}: {v}" for k, v in page.headers.items())

    gen = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        page.html,
        re.IGNORECASE,
    )
    if gen:
        result["meta_generator"] = gen.group(1)

    for name, sigs in SIGNATURES.items():
        for pattern, where in sigs:
            haystack = {"html": page.html, "headers": headers_blob, "server": server}[where]
            if re.search(pattern, haystack, re.IGNORECASE):
                result["cms"].append(name)
                break

    for name, pattern in TECH_PATTERNS.items():
        if re.search(pattern, page.html, re.IGNORECASE):
            result["technologies"].append(name)

    result["security_headers"] = {
        h: page.headers[h] for h in SECURITY_HEADERS if h in page.headers
    }
    return result
