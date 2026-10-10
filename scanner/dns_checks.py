"""DNS hygiene and DNSSEC checks (passive: ordinary public DNS queries only)."""
from __future__ import annotations

import dns.exception
import dns.resolver

from .common import Finding, ModuleResult

CAT = "DNS"

_res = dns.resolver.Resolver(configure=False)
_res.nameservers = ["1.1.1.1", "8.8.8.8"]
_res.timeout = 3
_res.lifetime = 6


def lookup(name: str, rtype: str):
    """Return (values, status); status is ok | nxdomain | noanswer | error."""
    try:
        ans = _res.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "noanswer"
    except (dns.exception.DNSException, OSError):
        return [], "error"
    out = []
    for r in ans:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        else:
            out.append(r.to_text())
    return out, "ok"


def check_dns(domain: str) -> ModuleResult:
    res = ModuleResult()
    f = res.findings

    a, a_status = lookup(domain, "A")
    aaaa, _ = lookup(domain, "AAAA")
    ns, _ = lookup(domain, "NS")
    mx, _ = lookup(domain, "MX")
    caa, _ = lookup(domain, "CAA")
    dnskey, _ = lookup(domain, "DNSKEY")
    ds, _ = lookup(domain, "DS")

    res.data = {"a": a, "aaaa": aaaa, "ns": ns, "mx": mx}

    if a_status == "nxdomain":
        f.append(Finding(CAT, "Domain does not exist (NXDOMAIN)", "high",
                         "The domain returned NXDOMAIN from public resolvers.",
                         "Check the spelling, or confirm the domain is registered and delegated."))
        return res

    if not a and not aaaa:
        f.append(Finding(CAT, "No A/AAAA record for the domain apex", "info",
                         "The bare domain does not point to a web server. This is fine if only www. or mail is used."))
    else:
        f.append(Finding(CAT, "Domain resolves", "pass", "A: " + (", ".join(a) or "none") +
                         ("; AAAA: " + ", ".join(aaaa) if aaaa else "")))

    if len(ns) < 2:
        f.append(Finding(CAT, "Fewer than two nameservers", "medium",
                         f"Found {len(ns)} NS record(s). A single nameserver is a single point of failure.",
                         "Use at least two nameservers, ideally on different networks."))
    else:
        f.append(Finding(CAT, "Redundant nameservers", "pass", ", ".join(sorted(ns))))

    if not caa:
        f.append(Finding(CAT, "No CAA record", "low",
                         "Without CAA any certificate authority may issue certificates for the domain.",
                         "Add a CAA record listing only the CA(s) you use, e.g. 0 issue \"letsencrypt.org\"."))
    else:
        f.append(Finding(CAT, "CAA record present", "pass", "; ".join(caa)))

    if dnskey and ds:
        f.append(Finding("DNSSEC", "DNSSEC enabled", "pass", "DNSKEY and DS records found; chain of trust published."))
    elif dnskey and not ds:
        f.append(Finding("DNSSEC", "DNSSEC signed but DS record missing at the parent", "medium",
                         "The zone has DNSKEY records but the parent zone has no DS record, so validators cannot trust it.",
                         "Publish the DS record with your registrar or remove the unused DNSKEY records."))
    else:
        f.append(Finding("DNSSEC", "DNSSEC not enabled", "low",
                         "Responses for this domain cannot be cryptographically validated, leaving room for DNS spoofing.",
                         "Enable DNSSEC at your DNS host and registrar if your registry and provider support it. "
                         "Support varies for .ke second-level domains, so confirm with your registrar."))
    return res
