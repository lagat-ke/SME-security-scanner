"""Orchestrates all modules and produces the scan result."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .common import Finding, ModuleResult, normalize_domain, score_findings, SEVERITIES
from .dns_checks import check_dns
from .email_auth import check_email
from .exposed import check_exposed
from .subdomains import check_subdomains
from .tls_check import check_tls
from .web_checks import check_web


def _safe(name, fn, *args) -> ModuleResult:
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - one failing module must not sink the scan
        return ModuleResult(findings=[Finding(name, "Check could not complete", "info",
                                              f"{type(e).__name__}: {str(e)[:160]}")])


def run_scan(raw_domain: str, check_ports: bool = False) -> dict:
    domain = normalize_domain(raw_domain)

    dns_res = _safe("DNS", check_dns, domain)
    if any(f.title.startswith("Domain does not exist") for f in dns_res.findings):
        # Nothing else can be assessed, so don't hand out a misleading grade.
        return _package(domain, dns_res.findings, dns_res.data, {}, 0, "?", [], [])

    has_mx = bool(dns_res.data.get("mx"))
    with ThreadPoolExecutor(max_workers=4) as ex:
        fut_email = ex.submit(_safe, "Email authentication", check_email, domain, has_mx)
        fut_tls = ex.submit(_safe, "SSL/TLS", check_tls, domain)
        fut_web = ex.submit(_safe, "HTTP headers", check_web, domain)
        fut_sub = ex.submit(_safe, "Subdomains", check_subdomains, domain)
        email_res, tls_res, web_res, sub_res = (x.result() for x in (fut_email, fut_tls, fut_web, fut_sub))

    subs = sub_res.data.get("subdomains", [])
    exp_res = _safe("Exposed services", check_exposed, domain, dns_res.data.get("a", []),
                    dns_res.data.get("mx", []), subs, bool(web_res.data.get("cdn")), check_ports)

    findings = []
    for r in (dns_res, tls_res, web_res, email_res, sub_res, exp_res):
        findings.extend(r.findings)
    # a plain-HTTP-only site also lacks HTTPS; avoid double-penalising identical root causes
    score, grade = score_findings(findings)

    meta = {
        "ips": dns_res.data.get("a", []) + dns_res.data.get("aaaa", []),
        "nameservers": dns_res.data.get("ns", []),
        "mx": dns_res.data.get("mx", []),
        "dkim_selectors": email_res.data.get("dkim_selectors", []),
        "cert_expires": tls_res.data.get("cert_expires"),
        "cert_days_left": tls_res.data.get("cert_days_left"),
        "cert_issuer": tls_res.data.get("cert_issuer"),
        "tls_negotiated": tls_res.data.get("negotiated"),
        "port_check": check_ports,
    }
    return _package(domain, findings, dns_res.data, meta, score, grade,
                    web_res.data.get("technologies", []), subs)


def _package(domain, findings, _dns, meta, score, grade, techs, subs) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score": score,
        "grade": grade,
        "counts": counts,
        "meta": meta,
        "technologies": techs,
        "subdomains": subs,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: order.get(f.severity, 9))],
    }
