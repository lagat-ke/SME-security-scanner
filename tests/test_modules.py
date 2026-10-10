"""Module logic tested against mocked network responses (no live traffic)."""
import ssl
from datetime import datetime, timedelta, timezone

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner import dns_checks, email_auth, tls_check, web_checks
from scanner.common import Fetch, Finding, score_findings


def fake_dns(table):
    def _lookup(name, rtype):
        v = table.get((name, rtype))
        return (v, "ok") if v else ([], "noanswer")
    return _lookup


def titles(res, sev=None):
    return [f.title for f in res.findings if sev is None or f.severity == sev]


def test_email_weak_config(monkeypatch):
    monkeypatch.setattr(email_auth, "lookup", fake_dns({
        ("a.co.ke", "TXT"): ["v=spf1 include:_spf.google.com +all"],
        ("_dmarc.a.co.ke", "TXT"): ["v=DMARC1; p=none"],
    }))
    r = email_auth.check_email("a.co.ke", has_mx=True)
    assert "SPF allows any sender (+all)" in titles(r, "critical")
    assert "DMARC in monitoring mode only (p=none)" in titles(r, "medium")
    assert "DMARC has no reporting address (rua)" in titles(r)


def test_email_good_config(monkeypatch):
    monkeypatch.setattr(email_auth, "lookup", fake_dns({
        ("a.co.ke", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_spf.google.com", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
        ("_dmarc.a.co.ke", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@a.co.ke"],
        ("google._domainkey.a.co.ke", "TXT"): ["v=DKIM1; k=rsa; p=ABC"],
    }))
    r = email_auth.check_email("a.co.ke", has_mx=True)
    assert not [f for f in r.findings if f.severity in ("critical", "high", "medium", "low")]
    assert r.data["dkim_selectors"] == ["google"]


def test_email_missing_everything(monkeypatch):
    monkeypatch.setattr(email_auth, "lookup", fake_dns({}))
    r = email_auth.check_email("a.co.ke", has_mx=True)
    assert "No SPF record" in titles(r, "high") and "No DMARC record" in titles(r, "high")


def test_spf_lookup_limit(monkeypatch):
    table = {("a.co.ke", "TXT"): ["v=spf1 " + " ".join(f"include:s{i}.x" for i in range(11)) + " -all"]}
    monkeypatch.setattr(email_auth, "lookup", fake_dns(table))
    assert email_auth.spf_lookup_count("a.co.ke") == 11
    r = email_auth.check_email("a.co.ke", has_mx=True)
    assert "SPF exceeds the 10 DNS-lookup limit" in titles(r)


def test_dns_dnssec_states(monkeypatch):
    base = {("a.co.ke", "A"): ["1.2.3.4"], ("a.co.ke", "NS"): ["ns1.x.", "ns2.x."]}
    monkeypatch.setattr(dns_checks, "lookup", fake_dns(base))
    assert "DNSSEC not enabled" in titles(dns_checks.check_dns("a.co.ke"))
    signed = {**base, ("a.co.ke", "DNSKEY"): ["257 3 13 abc"], ("a.co.ke", "DS"): ["1 13 2 abc"]}
    monkeypatch.setattr(dns_checks, "lookup", fake_dns(signed))
    assert "DNSSEC enabled" in titles(dns_checks.check_dns("a.co.ke"))
    half = {**base, ("a.co.ke", "DNSKEY"): ["257 3 13 abc"]}
    monkeypatch.setattr(dns_checks, "lookup", fake_dns(half))
    assert any("DS record missing" in t for t in titles(dns_checks.check_dns("a.co.ke")))


def _cert(days_left, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a.co.ke")])
    now = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(1).not_valid_before(now - timedelta(days=100))
         .not_valid_after(now + timedelta(days=days_left)).sign(key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def _run_tls(monkeypatch, der, verify_error=None, legacy=False):
    monkeypatch.setattr(tls_check, "_fetch_cert", lambda h: (der, "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "", 256), verify_error))
    monkeypatch.setattr(tls_check, "_accepts", lambda h, v: legacy if v in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1) else True)
    return tls_check.check_tls("a.co.ke")


def test_tls_expiry_bands(monkeypatch):
    assert "Certificate has expired" in titles(_run_tls(monkeypatch, _cert(-5)), "critical")
    assert any("expires in 7 days" in t for t in titles(_run_tls(monkeypatch, _cert(7, ), None), "high")) or \
        any("expires in 6 days" in t for t in titles(_run_tls(monkeypatch, _cert(7)), "high"))
    assert any("expires in" in t for t in titles(_run_tls(monkeypatch, _cert(25)), "medium"))
    assert any("valid for" in t for t in titles(_run_tls(monkeypatch, _cert(90)), "pass"))


def test_tls_problems(monkeypatch):
    r = _run_tls(monkeypatch, _cert(90), verify_error="self-signed certificate", legacy=True)
    assert "Self-signed certificate" in titles(r, "high")
    assert any("TLS 1.0" in t for t in titles(r, "medium"))
    r = _run_tls(monkeypatch, _cert(90, bits=1024))
    assert any("Weak RSA key" in t for t in titles(r, "high"))


def _fetch(url, status=200, headers=None, body="<html></html>", cookies=None):
    return Fetch(url, status, requests.structures.CaseInsensitiveDict(headers or {}), body, [url], cookies or [])


def test_web_headers_and_tech(monkeypatch):
    def fake_get(url, follow=True, **kw):
        if url.startswith("http://"):
            return _fetch(url, 200)  # no redirect
        if "security.txt" in url:
            return _fetch(url, 404)
        return _fetch(url, headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.3", "cf-ray": "x"},
                      body='<meta name="generator" content="WordPress 6.4"><link href="/wp-content/a.css">',
                      cookies=["PHPSESSID=abc; path=/"])
    monkeypatch.setattr(web_checks, "safe_get", fake_get)
    r = web_checks.check_web("a.co.ke")
    t = titles(r)
    assert "HTTP does not redirect to HTTPS" in t
    assert "Strict-Transport-Security missing" in t
    assert "No clickjacking protection" in t
    assert "Server header discloses software version" in t
    assert "Session/auth-style cookies without Secure flag" in t
    names = {x["name"] for x in r.data["technologies"]}
    assert {"WordPress", "PHP", "Cloudflare", "Apache"} <= names and r.data["cdn"] is True
    assert "No privacy notice link detected in the homepage HTML" in t


def test_web_unreachable(monkeypatch):
    def boom(*a, **k):
        raise ValueError("nope")
    monkeypatch.setattr(web_checks, "safe_get", boom)
    r = web_checks.check_web("a.co.ke")
    assert titles(r) == ["Website could not be fetched"]


def test_preference_cookie_not_medium_and_tech_deduped(monkeypatch):
    """Regression from a live Shopify/Cloudflare scan: 'localization' cookie flagged MEDIUM, 'cloudflare' listed twice."""
    def fake_get(url, follow=True, **kw):
        if url.startswith("http://"):
            return _fetch(url, 301, headers={"Location": "https://a.co.ke/"})
        if "security.txt" in url:
            return _fetch(url, 404)
        return _fetch(url, headers={"Server": "cloudflare", "cf-ray": "x", "x-shopify-stage": "p"},
                      body='<a href="/policies/privacy-policy">Privacy</a>', cookies=["localization=KE; path=/"])
    monkeypatch.setattr(web_checks, "safe_get", fake_get)
    r = web_checks.check_web("a.co.ke")
    assert not titles(r, "medium") or all("cookie" not in t.lower() for t in titles(r, "medium"))
    assert "Other cookies without Secure flag" in titles(r, "info")
    names = [x["name"].lower() for x in r.data["technologies"]]
    assert names.count("cloudflare") == 1
    assert any("managed platform" in t for t in titles(r, "info"))
    assert "Privacy notice link found on the homepage" in titles(r, "pass")
    assert "Referrer-Policy missing" in titles(r)


def test_good_site_not_failed_by_minor_items():
    fs = [Finding("x", "t", "medium")] * 2 + [Finding("x", "t", "low")] * 9
    assert score_findings(fs) == (80, "B")
