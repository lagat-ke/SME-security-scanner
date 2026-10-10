"""TLS and certificate checks using an ordinary client handshake."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .common import Finding, ModuleResult, resolve_public

CAT = "SSL/TLS"


def _connect(host: str, ctx: ssl.SSLContext, timeout: float = 8):
    ip = resolve_public(host)[0]
    sock = socket.create_connection((ip, 443), timeout=timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise


def _fetch_cert(host: str):
    """Return (der, protocol, cipher, verify_error)."""
    ctx = ssl.create_default_context()
    try:
        with _connect(host, ctx) as s:
            return s.getpeercert(binary_form=True), s.version(), s.cipher(), None
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with _connect(host, ctx) as s:
        return s.getpeercert(binary_form=True), s.version(), s.cipher(), verify_error


def _accepts(host: str, version: ssl.TLSVersion):
    """True/False if the server accepts exactly this protocol version, None if untestable."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with _connect(host, ctx, timeout=6):
            return True
    except ssl.SSLError:
        return False
    except OSError:
        return None


def _not_after(cert: x509.Certificate) -> datetime:
    dt = getattr(cert, "not_valid_after_utc", None)
    if dt is None:
        dt = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return dt


def check_tls(domain: str) -> ModuleResult:
    res = ModuleResult()
    f = res.findings

    host = None
    result = None
    last_err = None
    for candidate in (domain, "www." + domain):
        try:
            result = _fetch_cert(candidate)
            host = candidate
            break
        except Exception as e:  # noqa: BLE001 - report any connection failure
            last_err = e
    if result is None:
        f.append(Finding(CAT, "HTTPS is not available", "high",
                         f"Could not complete a TLS handshake on port 443 ({type(last_err).__name__}).",
                         "Install a TLS certificate (free options such as Let's Encrypt exist) and serve the site over HTTPS."))
        res.data["https"] = False
        return res
    res.data["https"] = True
    res.data["tls_host"] = host

    der, proto, cipher, verify_error = result
    cert = x509.load_der_x509_certificate(der)

    # ---- trust / hostname
    if verify_error:
        msg = verify_error.lower()
        if "hostname" in msg or "not valid for" in msg:
            f.append(Finding(CAT, "Certificate does not match the domain", "high", verify_error,
                             "Issue a certificate that lists this exact hostname in its Subject Alternative Names."))
        elif "expired" in msg:
            pass  # reported below with dates
        elif "self-signed" in msg or "self signed" in msg:
            f.append(Finding(CAT, "Self-signed certificate", "high", verify_error,
                             "Replace with a certificate from a trusted CA; browsers will warn visitors."))
        else:
            f.append(Finding(CAT, "Certificate is not trusted", "high", verify_error,
                             "Install the full certificate chain (including intermediates) from a trusted CA."))
    else:
        f.append(Finding(CAT, "Certificate chain is trusted and matches the hostname", "pass",
                         f"Issuer: {cert.issuer.rfc4514_string()}"))

    # ---- expiry
    expires = _not_after(cert)
    days = (expires - datetime.now(timezone.utc)).days
    res.data["cert_expires"] = expires.date().isoformat()
    res.data["cert_days_left"] = days
    res.data["cert_issuer"] = cert.issuer.rfc4514_string()
    if days < 0:
        f.append(Finding("Certificate expiry", "Certificate has expired", "critical",
                         f"Expired {-days} day(s) ago on {expires.date()}.",
                         "Renew immediately and set up automatic renewal."))
    elif days <= 14:
        f.append(Finding("Certificate expiry", f"Certificate expires in {days} days", "high",
                         f"Expires {expires.date()}.", "Renew now and enable auto-renewal."))
    elif days <= 30:
        f.append(Finding("Certificate expiry", f"Certificate expires in {days} days", "medium",
                         f"Expires {expires.date()}.", "Schedule renewal; enable auto-renewal if possible."))
    else:
        f.append(Finding("Certificate expiry", f"Certificate valid for {days} more days", "pass",
                         f"Expires {expires.date()}."))

    # ---- key and signature strength
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey) and pk.key_size < 2048:
        f.append(Finding(CAT, f"Weak RSA key ({pk.key_size}-bit)", "high",
                         "Keys under 2048 bits are considered breakable.", "Reissue with RSA 2048+ or ECDSA P-256."))
    elif isinstance(pk, rsa.RSAPublicKey):
        res.data["key"] = f"RSA {pk.key_size}"
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        res.data["key"] = f"ECDSA {pk.curve.name}"
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    if sig in ("sha1", "md5"):
        f.append(Finding(CAT, f"Certificate signed with weak hash ({sig.upper()})", "high",
                         "", "Reissue the certificate using SHA-256 or stronger."))

    # ---- protocol versions
    res.data["negotiated"] = f"{proto} / {cipher[0] if cipher else ''}"
    legacy = []
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if _accepts(host, ver):
            legacy.append(name)
    ssl3 = False
    if legacy:
        f.append(Finding(CAT, "Deprecated protocol versions enabled: " + ", ".join(legacy), "medium",
                         "TLS 1.0/1.1 were deprecated in 2021 (RFC 8996) and fail PCI-DSS requirements.",
                         "Disable TLS 1.0 and 1.1 in your web server / CDN settings; keep TLS 1.2 and 1.3."))
    t12 = _accepts(host, ssl.TLSVersion.TLSv1_2)
    t13 = _accepts(host, ssl.TLSVersion.TLSv1_3)
    if t13:
        f.append(Finding(CAT, "TLS 1.3 supported", "pass", f"Negotiated by default: {proto}."))
    elif t12:
        f.append(Finding(CAT, "TLS 1.3 not supported", "low", "TLS 1.2 is acceptable but 1.3 is faster and safer.",
                         "Enable TLS 1.3 if your server or CDN supports it."))
    elif t12 is False and t13 is False:
        f.append(Finding(CAT, "Server supports neither TLS 1.2 nor 1.3", "high", "",
                         "Enable TLS 1.2 and 1.3."))
    return res
