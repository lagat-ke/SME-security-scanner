# SME Security Scanner

A web app where a business enters its domain (e.g. `example.co.ke`) and gets a **passive** security assessment
with a professional PDF report. Built for small and medium businesses in Kenya, focused on the everyday weaknesses
that cause incidents: misconfiguration, exposed services and weak access controls.

## What it checks

| Area | Checks |
|---|---|
| DNS | resolution, nameserver redundancy, CAA |
| DNSSEC | DNSKEY + parent DS present |
| SSL/TLS | trusted chain, hostname match, key size, signature hash, TLS 1.0/1.1 enabled, TLS 1.3 support |
| Certificate expiry | critical (expired), high (<=14d), medium (<=30d) |
| HTTP headers | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking, HTTP->HTTPS redirect, cookie flags, version disclosure |
| Email | SPF (policy, multiple records, 10-lookup limit), DKIM (common selectors), DMARC (policy, rua, pct) |
| Subdomains | from public Certificate Transparency logs (crt.sh); sensitive names, dangling CNAMEs (takeover risk) |
| Exposed services | passive hostname review; **optional** TCP-connect check of 13 risky ports (RDP, SMB, databases, Telnet, FTP...) |
| Technology stack | server, CMS, frameworks, CDN/WAF, analytics from headers, cookies and page markup |
| Security configuration | `security.txt` |
| Privacy (preview) | privacy-notice link on the homepage (automated hint only, not a compliance finding) |

Output: a 0-100 score, an A-F grade, findings grouped by severity with plain-English fixes, and a PDF report
(executive summary, priority actions, detailed findings, technology and subdomain appendices, methodology).

## "Passive" and safety design

- Only public DNS, public CT logs, one normal TLS handshake and ordinary GET requests. No exploitation, brute-forcing or login attempts.
- The port check is **off by default** and requires the user to tick a box confirming they are authorised to test the domain.
- SSRF guard: every hostname (including each redirect hop) must resolve to a public IP before the server connects.
- Rate limit (10 scans/hour/client), input validation, strict CSP and security headers on the app itself, results kept in memory for 1 hour.
- Remote content is XML-escaped before it goes into the PDF.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
pytest -q                # 22 tests, no network needed
```

## Hosting (important)

**GitHub hosts the code, but GitHub Pages only serves static files and cannot run this Flask backend.**
Deploy the repo to any free Python/Docker host, such as Render, Fly.io, Railway, or a Hugging Face Space (Docker).
A `Dockerfile` is included:

```bash
docker build -t sme-scanner . && docker run -p 8000:8000 sme-scanner
```

Notes for production:
- Hosts must allow **outbound DNS, HTTPS (443) and, for the optional port check, arbitrary TCP**. Some free tiers restrict this.
- Behind a proxy, `X-Forwarded-For` is used for rate limiting; make sure your proxy sets it and strips client-supplied values.
- Results and rate-limit state are in memory, so run a single worker group (or add Redis) if you scale out.
- Add a short terms/privacy page: the app processes domain names submitted by users.

## Roadmap ideas

- ODPC / Data Protection Act self-assessment questionnaire alongside the technical scan (registration, privacy notice, DPO, breach process)
- Scheduled re-scans with email alerts for certificate expiry and DMARC changes
- Cloud misconfiguration checks (open S3/Azure/GCS buckets named after the domain)
- Swahili report option; branded white-label reports for IT providers
- Compare-over-time view and CSV export

## Limitations

Passive checks cannot see inside your network, applications, cloud accounts or devices. DKIM selectors cannot be enumerated,
so "not found" is a hint. This is not a penetration test or a compliance audit.
