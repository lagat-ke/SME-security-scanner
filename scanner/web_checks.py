"""HTTP security headers, cookies, redirect behaviour, technology fingerprinting,
security.txt and a privacy-notice preview. Uses ordinary GET requests only."""
from __future__ import annotations

import re

import requests

from .common import Finding, ModuleResult, safe_get

CAT = "HTTP headers"

HEADER_RULES = [
    
    ("strict-transport-security", "medium",
     "HSTS tells browsers to only use HTTPS, preventing downgrade and cookie-stealing attacks.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "medium",
     "A Content-Security-Policy limits where scripts can load from and is the main defence against XSS.",
     "Start with a report-only policy, then enforce, e.g. default-src 'self'."),
    ("x-content-type-options", "low",
     "Without nosniff, browsers may guess content types and execute uploaded files as scripts.",
     "Add: X-Content-Type-Options: nosniff"),
    ("referrer-policy", "low",
     "Without a Referrer-Policy, full URLs (possibly containing tokens or IDs) can leak to third parties.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "low",
     "Restricts powerful browser features (camera, microphone, geolocation) for your pages and embeds.",
     "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
]

TECH_SIGNATURES = [
    ("WordPress", r"wp-content|wp-includes|/wp-json/", "CMS"),
    ("Joomla", r"/media/jui/|content=\"Joomla", "CMS"),
    ("Drupal", r"Drupal\.settings|content=\"Drupal", "CMS"),
    ("Shopify", r"cdn\.shopify\.com|Shopify\.theme", "E-commerce"),
    ("WooCommerce", r"woocommerce", "E-commerce"),
    ("Wix", r"static\.wixstatic\.com|wix-", "Site builder"),
    ("Squarespace", r"static1\.squarespace\.com|squarespace", "Site builder"),
    ("Magento", r"Mage\.Cookies|/static/frontend/Magento", "E-commerce"),
    ("React", r"data-reactroot|__NEXT_DATA__|react\.production", "JS framework"),
    ("Vue.js", r"data-v-[0-9a-f]{6,}|vue\.(min\.)?js", "JS framework"),
    ("Angular", r"ng-version=|<app-root", "JS framework"),
    ("jQuery", r"jquery[.-][\d.]*(min\.)?js", "JS library"),
    ("Bootstrap", r"bootstrap[.-][\d.]*(min\.)?(css|js)", "CSS framework"),
    ("Google Analytics", r"googletagmanager\.com|google-analytics\.com|gtag\(", "Analytics"),
    ("Facebook Pixel", r"connect\.facebook\.net|fbq\(", "Analytics"),
]

HEADER_TECH = {
    "cf-ray": ("Cloudflare", "CDN/WAF"),
    "x-sucuri-id": ("Sucuri", "CDN/WAF"),
    "x-amz-cf-id": ("Amazon CloudFront", "CDN"),
    "x-vercel-id": ("Vercel", "Hosting"),
    "x-nf-request-id": ("Netlify", "Hosting"),
    "x-github-request-id": ("GitHub Pages", "Hosting"),
    "x-wp-total": ("WordPress", "CMS"),
    "x-drupal-cache": ("Drupal", "CMS"),
    "x-shopify-stage": ("Shopify", "E-commerce"),
}

COOKIE_TECH = {
    "phpsessid": ("PHP", "Language"),
    "asp.net_sessionid": ("ASP.NET", "Framework"),
    "jsessionid": ("Java", "Language"),
    "laravel_session": ("Laravel", "Framework"),
    "csrftoken": ("Django", "Framework"),
    "_shopify_s": ("Shopify", "E-commerce"),
}

VERSION_RE = re.compile(r"\d+\.\d+")
SENSITIVE_COOKIE_RE = re.compile(r"sess|auth|token|login|jwt|csrf|xsrf|^sid$|_sid$|user|account", re.I)
MANAGED_PLATFORMS = ("Shopify", "Wix", "Squarespace", "GitHub Pages", "Vercel", "Netlify")


def _pretty(header: str) -> str:
    return "-".join(w.capitalize() for w in header.split("-"))


def _cookie_findings(label, names, sensitive_sev, fix):
    """Rate by cookie sensitivity: unknown/preference cookies are informational only."""
    sens = sorted({n for n in names if SENSITIVE_COOKIE_RE.search(n)})
    other = sorted({n for n in names} - set(sens))
    out = []
    if sens:
        out.append(Finding(CAT, f"Session/auth-style cookies {label}", sensitive_sev, ", ".join(sens), fix))
    if other:
        out.append(Finding(CAT, f"Other cookies {label}", "info",
                           ", ".join(other) + ". These look like preference or analytics cookies, so the risk is low.", fix))
    return out


def _cookie_issues(set_cookies: list[str]):
    missing_secure, missing_httponly, missing_samesite = [], [], []
    for c in set_cookies:
        parts = [p.strip() for p in c.split(";")]
        name = parts[0].split("=")[0]
        flags = {p.lower().split("=")[0] for p in parts[1:]}
        if "secure" not in flags:
            missing_secure.append(name)
        if "httponly" not in flags:
            missing_httponly.append(name)
        if "samesite" not in flags:
            missing_samesite.append(name)
    return missing_secure, missing_httponly, missing_samesite


def check_web(domain: str) -> ModuleResult:
    res = ModuleResult()
    f = res.findings
    techs: dict[str, str] = {}

    page = None
    last_err = None
    for host in (domain, "www." + domain):
        try:
            page = safe_get(f"https://{host}/", max_bytes=2_000_000)
            break
        except Exception as e:  # noqa: BLE001
            last_err = e
    if page is None:
        
        try:
            page = safe_get(f"http://{domain}/")
            f.append(Finding(CAT, "Website only reachable over plain HTTP", "high",
                             "The site did not answer over HTTPS but did over HTTP; traffic is unencrypted.",
                             "Enable HTTPS and redirect all HTTP traffic to it."))
        except Exception:  # noqa: BLE001
            f.append(Finding(CAT, "Website could not be fetched", "info",
                             f"No web response was received ({type(last_err).__name__}). "
                             "The domain may not host a website, or it blocks automated requests."))
            res.data = {"technologies": [], "cdn": False, "reachable": False}
            return res

    res.data["reachable"] = True
    res.data["final_url"] = page.url
    h = page.headers
    is_https = page.url.startswith("https://")

  
    try:
        plain = safe_get(f"http://{domain}/", follow=False, timeout=8)
        loc = plain.headers.get("Location", "")
        if plain.status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
            f.append(Finding(CAT, "HTTP redirects to HTTPS", "pass", f"{plain.status} -> {loc}"))
        elif plain.status in (301, 302, 307, 308):
            f.append(Finding(CAT, "HTTP does not redirect straight to HTTPS", "low",
                             f"Redirects to {loc or 'unknown'} first.", "Redirect HTTP directly to the https:// URL."))
        else:
            f.append(Finding(CAT, "HTTP does not redirect to HTTPS", "medium",
                             f"http://{domain}/ answered {plain.status} without redirecting.",
                             "Add a permanent (301) redirect from HTTP to HTTPS."))
    except (requests.RequestException, ValueError, OSError):
        pass 

    
    if is_https:
        for name, sev, why, fix in HEADER_RULES:
            if name in h:
                f.append(Finding(CAT, f"{_pretty(name)} present", "pass", h[name][:200]))
            elif name == "strict-transport-security":
                f.append(Finding(CAT, "Strict-Transport-Security missing", sev, why, fix))
            else:
                f.append(Finding(CAT, f"{_pretty(name)} missing", sev, why, fix))
        csp = h.get("content-security-policy", "")
        if "x-frame-options" in h or "frame-ancestors" in csp:
            f.append(Finding(CAT, "Clickjacking protection present", "pass",
                             h.get("x-frame-options", "frame-ancestors in CSP")))
        else:
            f.append(Finding(CAT, "No clickjacking protection", "medium",
                             "Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be embedded in a hostile page.",
                             "Add: X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self')."))
        if "unsafe-inline" in csp and "script-src" in csp:
            f.append(Finding(CAT, "CSP allows 'unsafe-inline' scripts", "low",
                             "This weakens the protection a CSP gives against XSS.",
                             "Use nonces or hashes instead of 'unsafe-inline'."))

    
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    for label, val in (("Server", server), ("X-Powered-By", powered)):
        if val and VERSION_RE.search(val):
            f.append(Finding(CAT, f"{label} header discloses software version", "low", val,
                             "Hide version numbers so attackers cannot easily match them to known vulnerabilities."))
    if server:
        techs[server.split("/")[0]] = "Web server"
    if powered:
        techs[powered.split("/")[0]] = "Runtime"

   
    ms, mh, msa = _cookie_issues(page.set_cookies)
    if page.set_cookies:
        if ms and is_https:
            f.extend(_cookie_findings("without Secure flag", ms, "medium",
                                      "Set the Secure attribute so cookies are never sent over HTTP."))
        if mh:
            f.extend(_cookie_findings("without HttpOnly flag", mh, "low",
                                      "Set HttpOnly on session cookies so scripts cannot read them."))
        if msa:
            f.extend(_cookie_findings("without SameSite attribute", msa, "low",
                                      "Set SameSite=Lax or Strict to reduce CSRF risk."))
        if not (ms or mh or msa):
            f.append(Finding(CAT, "Cookie flags look good", "pass", "Secure, HttpOnly and SameSite are set."))

    
    for hdr, (tech, kind) in HEADER_TECH.items():
        if hdr in h:
            techs[tech] = kind
    for c in page.set_cookies:
        cname = c.split("=")[0].strip().lower()
        for key, (tech, kind) in COOKIE_TECH.items():
            if cname.startswith(key):
                techs[tech] = kind
    body = page.body
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        gen = m.group(1)[:80]
        techs[gen] = "Generator"
        if VERSION_RE.search(gen):
            f.append(Finding(CAT, "Site generator version is public", "low", gen,
                             "Remove the generator meta tag and keep the CMS updated."))
    for tech, pat, kind in TECH_SIGNATURES:
        if re.search(pat, body, re.I):
            techs.setdefault(tech, kind)
    
    merged: dict[str, tuple[str, str]] = {}
    for k, v in techs.items():
        key = k.lower()
        name = k.capitalize() if k.islower() else k
        if key not in merged or v in ("CDN/WAF", "CDN"):
            merged[key] = (name, v)
    res.data["technologies"] = [{"name": n, "type": t} for n, t in sorted(merged.values())]
    techs = {n: t for n, t in merged.values()}
    platform = next((n for n in techs if n in MANAGED_PLATFORMS), None)
    if platform:
        f.append(Finding("Security configuration", f"Hosted on a managed platform ({platform})", "info",
                         "On managed platforms, TLS, security headers and cookies are controlled by the provider, "
                         "so some findings above cannot be changed by you directly.",
                         f"Raise header/cookie gaps with {platform} support, and focus your own effort on what you control: "
                         "DNS (CAA, DNSSEC), email authentication, account security (MFA) and unused subdomains."))
    res.data["cdn"] = any(v == "CDN/WAF" or v == "CDN" for v in techs.values())

    
    has_security_txt = False
    try:
        st = safe_get(f"https://{domain}/.well-known/security.txt", timeout=6, max_bytes=20_000)
        has_security_txt = st.status == 200 and "contact:" in st.body.lower()
    except (requests.RequestException, ValueError, OSError):
        pass
    if has_security_txt:
        f.append(Finding("Security configuration", "security.txt published", "pass",
                         "Researchers have a documented way to report vulnerabilities."))
    else:
        f.append(Finding("Security configuration", "No security.txt", "info",
                         "There is no /.well-known/security.txt telling researchers how to report issues.",
                         "Publish one with a Contact: line (see securitytxt.org)."))

    
    has_privacy = bool(re.search(r'<a[^>]+href=["\'][^"\']*privacy[^"\']*["\']|>\s*privacy\s+(policy|notice|statement)',
                                 body, re.I))
    if has_privacy:
        f.append(Finding("Privacy (preview)", "Privacy notice link found on the homepage", "pass",
                         "A visible privacy notice is a baseline transparency expectation."))
    else:
        f.append(Finding("Privacy (preview)", "No privacy notice link detected in the homepage HTML", "info",
                         "The link may exist but be loaded by JavaScript or sit beyond the part of the page we read, so this is "
                         "only a prompt to check manually. If you collect personal data (forms, orders, analytics), the Data "
                         "Protection Act, 2019 expects you to tell people how it is processed. Not a compliance finding.",
                         "Confirm a privacy notice is linked from every page footer. See the ODPC guidance for MSMEs."))
    return res
