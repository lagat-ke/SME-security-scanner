"""SPF, DKIM and DMARC checks (public DNS TXT lookups only)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .common import Finding, ModuleResult
from .dns_checks import lookup

CAT = "Email authentication"

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "zmail", "protonmail", "protonmail2",
    "protonmail3", "everlytickey1", "cm", "sendgrid", "amazonses", "mailo", "fm1", "fm2", "fm3",
]


def _spf_record(domain: str):
    txts, _ = lookup(domain, "TXT")
    recs = [t for t in txts if t.lower().startswith("v=spf1")]
    return recs


def spf_lookup_count(domain: str, seen=None, depth: int = 0) -> int:
    """Approximate the number of DNS-querying terms (limit is 10 per RFC 7208)."""
    seen = seen if seen is not None else set()
    if depth > 6 or domain in seen:
        return 0
    seen.add(domain)
    recs = _spf_record(domain)
    if not recs:
        return 0
    n = 0
    for tok in recs[0].split()[1:]:
        t = tok.lstrip("+-~?").lower()
        if t.startswith("include:"):
            n += 1 + spf_lookup_count(t[8:], seen, depth + 1)
        elif t.startswith("redirect="):
            n += 1 + spf_lookup_count(t[9:], seen, depth + 1)
        elif t.split(":")[0].split("/")[0] in ("a", "mx", "ptr", "exists"):
            n += 1
    return n


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_email(domain: str, has_mx: bool) -> ModuleResult:
    res = ModuleResult()
    f = res.findings

    # ---- SPF
    spf = _spf_record(domain)
    if len(spf) > 1:
        f.append(Finding(CAT, "Multiple SPF records", "high",
                         "More than one v=spf1 TXT record exists; receivers treat this as a permanent error and SPF fails.",
                         "Merge everything into a single SPF record."))
    elif not spf:
        sev = "high" if has_mx else "medium"
        f.append(Finding(CAT, "No SPF record", sev,
                         "Anyone can send email claiming to be from this domain without failing SPF.",
                         "Publish a TXT record such as: v=spf1 include:<your mail provider> -all"
                         if has_mx else "If this domain sends no email, publish: v=spf1 -all"))
    else:
        rec = spf[0]
        low = rec.lower().split()
        if "+all" in low or "all" in low:
            f.append(Finding(CAT, "SPF allows any sender (+all)", "critical", rec,
                             "Replace +all with -all (or ~all while testing)."))
        elif "?all" in low:
            f.append(Finding(CAT, "SPF is neutral (?all)", "medium", rec,
                             "Change ?all to ~all, then -all once you have confirmed all legitimate senders."))
        elif "~all" in low:
            f.append(Finding(CAT, "SPF uses soft-fail (~all)", "low", rec,
                             "Move to -all once all legitimate senders are covered."))
        elif "-all" in low or any(t.startswith("redirect=") for t in low):
            f.append(Finding(CAT, "SPF policy is strict", "pass", rec))
        else:
            f.append(Finding(CAT, "SPF has no terminating 'all'", "medium", rec,
                             "End the record with -all so unlisted senders are rejected."))
        n = spf_lookup_count(domain)
        if n > 10:
            f.append(Finding(CAT, "SPF exceeds the 10 DNS-lookup limit", "medium",
                             f"Approximately {n} lookups. Receivers return a permanent error above 10, breaking SPF.",
                             "Remove unused include: entries or flatten the record."))

    # ---- DMARC
    txts, _ = lookup(f"_dmarc.{domain}", "TXT")
    dm = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dm:
        f.append(Finding(CAT, "No DMARC record", "high" if has_mx else "medium",
                         "Without DMARC, receivers have no instruction on what to do with spoofed email, "
                         "making business-email-compromise and phishing in your name easier.",
                         "Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain, review reports, "
                         "then move to p=quarantine and p=reject."))
    else:
        tags = parse_dmarc(dm[0])
        p = tags.get("p", "").lower()
        if p == "reject":
            f.append(Finding(CAT, "DMARC enforced (p=reject)", "pass", dm[0]))
        elif p == "quarantine":
            f.append(Finding(CAT, "DMARC quarantines failures (p=quarantine)", "low", dm[0],
                             "Consider p=reject once reports show legitimate mail passes."))
        else:
            f.append(Finding(CAT, "DMARC in monitoring mode only (p=none)", "medium", dm[0],
                             "p=none does not block spoofed mail. Review reports and move to quarantine/reject."))
        if "rua" not in tags:
            f.append(Finding(CAT, "DMARC has no reporting address (rua)", "low",
                             "You will not receive aggregate reports showing who sends mail as your domain.",
                             "Add rua=mailto:<address>."))
        pct = tags.get("pct")
        if pct and pct.isdigit() and int(pct) < 100 and p in ("quarantine", "reject"):
            f.append(Finding(CAT, f"DMARC applies to only {pct}% of mail", "low",
                             "Policy is partially enforced.", "Raise pct to 100 when ready."))

    # ---- DKIM (selectors are not discoverable; probe common ones)
    def probe(sel):
        recs, _ = lookup(f"{sel}._domainkey.{domain}", "TXT")
        cname, _ = lookup(f"{sel}._domainkey.{domain}", "CNAME")
        if any("p=" in r for r in recs) or cname:
            return sel
        return None

    with ThreadPoolExecutor(max_workers=8) as ex:
        found = [s for s in ex.map(probe, DKIM_SELECTORS) if s]
    res.data["dkim_selectors"] = found
    if found:
        f.append(Finding(CAT, "DKIM key published", "pass", "Selector(s) found: " + ", ".join(found)))
    elif has_mx:
        f.append(Finding(CAT, "No DKIM key found at common selectors", "low",
                         "DKIM selectors can be any name, so this does not prove DKIM is absent, "
                         "but none of the " + str(len(DKIM_SELECTORS)) + " common selectors were found.",
                         "Confirm DKIM signing is enabled with your mail provider (Google Workspace, Microsoft 365, Zoho, etc.) "
                         "and that the DKIM DNS record is published."))
    return res
