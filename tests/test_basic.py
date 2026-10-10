import pytest

from scanner.common import Finding, normalize_domain, score_findings
from scanner.email_auth import parse_dmarc
from report import build_pdf


@pytest.mark.parametrize("raw,expected", [
    ("Example.co.ke", "example.co.ke"),
    ("https://www.example.co.ke/path?x=1", "www.example.co.ke"),
    ("  example.com:8080 ", "example.com"),
    ("user@example.com", "example.com"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "10.0.0.1", "exa mple.com", "-bad.com", "a" * 70 + ".com"])
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_dmarc_parse():
    t = parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@b.co.ke; pct=100")
    assert t["p"] == "reject" and t["pct"] == "100"


def test_scoring():
    fs = [Finding("x", "t", "critical"), Finding("x", "t", "high"), Finding("x", "t", "pass")]
    assert score_findings(fs) == (60, "D")


def test_pdf_builds_with_hostile_text():
    result = {
        "domain": "example.co.ke", "scanned_at": "2026-10-10T12:00:00+00:00", "score": 55, "grade": "D",
        "counts": {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0, "pass": 1},
        "meta": {"ips": ["1.2.3.4"], "nameservers": ["ns1.x."], "mx": [], "port_check": False,
                 "cert_expires": "2027-01-01", "cert_days_left": 83, "tls_negotiated": "TLSv1.3"},
        "technologies": [{"name": "<b>WordPress</b>", "type": "CMS"}],
        "subdomains": [{"name": "dev.example.co.ke", "ips": ["1.2.3.4"], "cname": "", "live": True, "dangling": False}],
        "findings": [
            {"category": "DNS", "title": "Bad <script>&", "severity": "critical", "detail": "x < y & z", "fix": "Do <this>"},
            {"category": "SSL/TLS", "title": "Odd category", "severity": "medium", "detail": "", "fix": "f"},
            {"category": "Brand new category", "title": "ok", "severity": "pass", "detail": "", "fix": ""},
        ],
    }
    pdf = build_pdf(result)
    assert pdf[:4] == b"%PDF" and len(pdf) > 3000
