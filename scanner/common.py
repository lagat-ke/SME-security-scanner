"""Shared helpers: finding model, domain validation, SSRF-safe HTTP fetching."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse

import requests

SEVERITIES = ["critical", "high", "medium", "low", "info", "pass"]
USER_AGENT = "SME-Security-Scanner/1.0 (passive assessment; +https://github.com/)"

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


@dataclass
class Finding:
    category: str
    title: str
    severity: str  # one of SEVERITIES
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModuleResult:
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)


def normalize_domain(raw: str) -> str:
    """Return a clean lowercase ASCII hostname or raise ValueError."""
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("That doesn't look like a valid domain name.")
    if not DOMAIN_RE.match(d):
        raise ValueError("Enter a domain like example.co.ke (no spaces or paths).")
    try:
        ipaddress.ip_address(d)
        raise ValueError("Enter a domain name, not an IP address.")
    except ValueError as e:
        if "domain name" in str(e):
            raise
    return d


def resolve_public(host: str) -> list[str]:
    """Resolve host; raise ValueError if it points at a non-public address (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"{host} does not resolve")
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ValueError(f"{host} does not resolve")
    for ip in ips:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError(f"{host} resolves to a non-public address; refusing to connect")
    return ips


@dataclass
class Fetch:
    url: str
    status: int
    headers: requests.structures.CaseInsensitiveDict
    body: str
    chain: list
    set_cookies: list


def safe_get(url: str, max_redirects: int = 5, timeout: int = 10, follow: bool = True,
             max_bytes: int = 500_000) -> Fetch:
    """GET with manual redirect handling; every hop is checked to be a public host."""
    chain: list[str] = []
    cookies: list[str] = []
    current = url
    for _ in range(max_redirects + 1):
        p = urlparse(current)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Unsupported redirect target")
        resolve_public(p.hostname)
        resp = requests.get(current, headers={"User-Agent": USER_AGENT}, timeout=timeout,
                            allow_redirects=False, stream=True)
        try:
            cookies.extend(resp.raw.headers.getlist("Set-Cookie"))
            chain.append(current)
            if follow and resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                current = urljoin(current, resp.headers["Location"])
                continue
            body = b""
            for chunk in resp.iter_content(8192):
                body += chunk
                if len(body) >= max_bytes:
                    break
            return Fetch(current, resp.status_code, resp.headers,
                         body.decode(resp.encoding or "utf-8", "replace"), chain, cookies)
        finally:
            resp.close()
    raise ValueError("Too many redirects")


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    # Serious issues dominate; many minor hygiene items must not drag a solid setup into a failing grade,
    # so total deduction for low-severity items is capped.
    weights = {"critical": 25, "high": 15, "medium": 5, "low": 2}
    score = 100
    low_total = 0
    for f in findings:
        w = weights.get(f.severity, 0)
        if f.severity == "low":
            low_total += w
            continue
        score -= w
    score -= min(low_total, 10)
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return score, grade
