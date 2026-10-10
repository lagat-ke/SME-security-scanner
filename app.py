"""SME Security Scanner - Flask app."""
from __future__ import annotations

import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request, send_file, send_from_directory
import io

from report import build_pdf
from scanner.common import normalize_domain
from scanner.scan import run_scan

app = Flask(__name__, static_folder="static", static_url_path="/static")

_results: dict[str, tuple[float, dict]] = {}
_hits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()
RESULT_TTL = 3600
RATE_LIMIT = 10  # scans per hour per client
RATE_WINDOW = 3600


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


def _rate_limited(ip: str) -> bool:
    now = time.time()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return True
        q.append(now)
        return False


def _store(result: dict) -> str:
    now = time.time()
    with _lock:
        for k in [k for k, (t, _) in _results.items() if now - t > RESULT_TTL]:
            del _results[k]
        if len(_results) > 300:
            oldest = min(_results, key=lambda k: _results[k][0])
            del _results[oldest]
        rid = secrets.token_urlsafe(12)
        _results[rid] = (now, result)
    return rid


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                               "script-src 'self'; frame-ancestors 'none'")
    return resp


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/healthz")
def health():
    return {"ok": True}


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    try:
        domain = normalize_domain(data.get("domain", ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    check_ports = bool(data.get("check_ports")) and bool(data.get("confirm_ownership"))
    if data.get("check_ports") and not data.get("confirm_ownership"):
        return jsonify(error="Confirm you are authorised to test this domain to enable the port check."), 400
    if _rate_limited(_client_ip()):
        return jsonify(error="Rate limit reached (10 scans per hour). Please try again later."), 429
    result = run_scan(domain, check_ports=check_ports)
    result["id"] = _store(result)
    return jsonify(result)


@app.get("/api/report/<rid>.pdf")
def api_report(rid):
    with _lock:
        entry = _results.get(rid)
    if not entry:
        return jsonify(error="Report expired. Please run the scan again."), 404
    pdf = build_pdf(entry[1])
    return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"security-assessment-{entry[1]['domain']}.pdf")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
