"""Subdomain discovery from public Certificate Transparency logs (crt.sh) - fully passive:
no guessing or brute-forcing against the target's own servers."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import requests

from .common import Finding, ModuleResult, USER_AGENT
from .dns_checks import lookup

CAT = "Subdomains"
MAX_RESOLVE = 60

RISKY_LABELS = {
    "admin": "administration interface", "administrator": "administration interface",
    "cpanel": "hosting control panel", "whm": "hosting control panel", "plesk": "hosting control panel",
    "phpmyadmin": "database admin tool", "pma": "database admin tool", "adminer": "database admin tool",
    "dev": "development environment", "test": "test environment", "staging": "staging environment",
    "stage": "staging environment", "uat": "test environment", "qa": "test environment", "demo": "demo environment",
    "vpn": "remote access gateway", "rdp": "remote desktop", "remote": "remote access",
    "jenkins": "CI server", "gitlab": "source-code server", "git": "source-code server",
    "grafana": "monitoring dashboard", "kibana": "log dashboard", "db": "database host", "mysql": "database host",
    "sql": "database host", "backup": "backup host", "old": "legacy site", "legacy": "legacy site",
    "ftp": "file transfer service", "sftp": "file transfer service", "webmail": "webmail login",
    "portal": "login portal", "erp": "business system", "crm": "business system",
}

# CNAME targets of services where an unclaimed resource can be taken over.
TAKEOVER_SUFFIXES = (
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudapp.net", "s3.amazonaws.com",
    "s3-website", "elasticbeanstalk.com", "trafficmanager.net", "blob.core.windows.net",
    "netlify.app", "surge.sh", "readthedocs.io", "ghost.io", "myshopify.com", "zendesk.com",
)


def _ct_names(domain: str) -> list[str]:
    r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                     headers={"User-Agent": USER_AGENT}, timeout=25)
    r.raise_for_status()
    names = set()
    for row in r.json():
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == domain or n.endswith("." + domain):
                if re.fullmatch(r"[a-z0-9.-]+", n):
                    names.add(n)
    return sorted(names)


def check_subdomains(domain: str) -> ModuleResult:
    res = ModuleResult()
    f = res.findings
    try:
        names = _ct_names(domain)
    except Exception as e:  # noqa: BLE001
        f.append(Finding(CAT, "Certificate Transparency lookup unavailable", "info",
                         f"crt.sh did not respond ({type(e).__name__}); subdomain discovery was skipped. Try again later."))
        res.data["subdomains"] = []
        return res

    subs = [n for n in names if n != domain]
    res.data["subdomain_count"] = len(subs)

    def resolve(n):
        cname, _ = lookup(n, "CNAME")
        a, st = lookup(n, "A")
        target = cname[0].rstrip(".") if cname else ""
        dangling = False
        if target:
            _, tst = lookup(target, "A")
            dangling = tst == "nxdomain"
        return {"name": n, "ips": a, "cname": target, "live": bool(a), "dangling": dangling}

    with ThreadPoolExecutor(max_workers=10) as ex:
        info = list(ex.map(resolve, subs[:MAX_RESOLVE]))
    # Anything beyond the cap is listed but unresolved.
    info += [{"name": n, "ips": [], "cname": "", "live": None, "dangling": False} for n in subs[MAX_RESOLVE:]]
    res.data["subdomains"] = info

    if not subs:
        f.append(Finding(CAT, "No subdomains found in public certificate logs", "info",
                         "Only the main domain appears in Certificate Transparency logs."))
        return res

    f.append(Finding(CAT, f"{len(subs)} subdomain(s) found in certificate logs", "info",
                     "Every hostname that has had a public certificate is visible to attackers. "
                     "Review the list in the report appendix for anything you no longer use."))

    risky = []
    for s in info:
        label = s["name"][: -(len(domain) + 1)].split(".")[-1] if s["name"] != domain else ""
        for key, desc in RISKY_LABELS.items():
            if label == key or label.startswith(key + "-") or label.endswith("-" + key):
                if s["live"] is not False:
                    risky.append((s["name"], desc))
                break
    if risky:
        f.append(Finding(CAT, "Sensitive-looking subdomains are publicly named", "medium",
                         "; ".join(f"{n} ({d})" for n, d in risky[:15]),
                         "Make sure each is protected by strong authentication (and MFA), restricted by IP/VPN where "
                         "possible, and decommissioned if unused. Development and staging sites are often left with weak defaults."))

    dangling = [s for s in info if s["dangling"]]
    for s in dangling:
        takeover = s["cname"].endswith(TAKEOVER_SUFFIXES) or any(t in s["cname"] for t in TAKEOVER_SUFFIXES)
        f.append(Finding(CAT, f"Dangling DNS record: {s['name']}", "high" if takeover else "medium",
                         f"CNAME points to {s['cname']}, which no longer resolves."
                         + (" This provider is commonly subject to subdomain takeover." if takeover else ""),
                         "Delete the DNS record if the service is no longer used, or re-create the resource."))

    stale = [s for s in info if s["live"] is False and not s["dangling"]]
    if len(stale) >= 5:
        f.append(Finding(CAT, f"{len(stale)} subdomains in certificate logs no longer resolve", "low",
                         "Old DNS clean-up is incomplete; stale names make takeover and phishing look-alikes easier.",
                         "Remove unused DNS records."))
    return res
