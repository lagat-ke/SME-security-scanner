"""Exposed-service detection.

Default (passive): inferred from public DNS only - mail hosts and sensitive hostnames.
Opt-in (light active): a single TCP connect (no payloads, no banner grabbing, no exploits) to a short
list of well-known service ports on the domain's own IP. This is only run after the user
confirms they are authorised to test the domain.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .common import Finding, ModuleResult, resolve_public

CAT = "Exposed services"

# port: (service, severity if open to the internet, advice)
PORTS = {
    21: ("FTP", "medium", "FTP sends passwords in clear text. Use SFTP/FTPS and restrict by IP."),
    22: ("SSH", "low", "Restrict SSH to known IPs or a VPN, disable password login and use keys + fail2ban."),
    23: ("Telnet", "critical", "Telnet is unencrypted and obsolete. Disable it immediately."),
    445: ("SMB file sharing", "critical", "SMB must never be internet-facing (ransomware vector). Block at the firewall."),
    1433: ("Microsoft SQL Server", "critical", "Databases must not be reachable from the internet. Bind to localhost/private network."),
    3306: ("MySQL/MariaDB", "critical", "Databases must not be reachable from the internet. Bind to localhost/private network."),
    3389: ("Remote Desktop (RDP)", "critical", "Exposed RDP is a leading ransomware entry point. Put it behind a VPN with MFA."),
    5432: ("PostgreSQL", "critical", "Databases must not be reachable from the internet. Bind to localhost/private network."),
    5900: ("VNC remote desktop", "high", "Put VNC behind a VPN; never expose it directly."),
    6379: ("Redis", "critical", "Redis commonly has no authentication. Bind to localhost and require a password."),
    9200: ("Elasticsearch", "critical", "Exposed Elasticsearch has caused many data leaks. Restrict to private network."),
    27017: ("MongoDB", "critical", "Exposed MongoDB has caused many data leaks. Restrict to private network."),
    8080: ("Alternative HTTP", "info", "Check this is intentional and not an admin panel or test site."),
}


def _probe(args):
    ip, port = args
    try:
        with socket.create_connection((ip, port), timeout=2.5):
            return port
    except OSError:
        return None


def check_exposed(domain: str, a_records: list[str], mx_hosts: list[str], subdomains: list[dict],
                  cdn: bool, active: bool) -> ModuleResult:
    res = ModuleResult()
    f = res.findings

    # ---- passive: what DNS itself reveals
    exposed_names = [s["name"] for s in subdomains
                     if s.get("live") and any(
                         s["name"].startswith(p + ".") for p in
                         ("ftp", "rdp", "vpn", "ssh", "db", "mysql", "sql", "phpmyadmin", "cpanel", "whm", "plesk", "remote"))]
    if exposed_names:
        f.append(Finding(CAT, "Hostnames suggest internet-facing admin or data services", "medium",
                         ", ".join(exposed_names[:12]),
                         "Verify each is intentional and access-controlled. Use the opt-in port check to confirm which are open."))
    else:
        f.append(Finding(CAT, "No obviously sensitive service hostnames found in DNS", "pass",
                         "Passive review of discovered hostnames found no ftp/rdp/db/admin-style names."))

    if not active:
        f.append(Finding(CAT, "Port check not run", "info",
                         "Open-port testing is optional and requires confirmation that you are authorised to test the domain. "
                         "Re-run with the option enabled to check for exposed databases, RDP, FTP and similar."))
        return res

    if not a_records:
        f.append(Finding(CAT, "Port check skipped: no A record", "info"))
        return res
    try:
        ip = resolve_public(domain)[0]
    except ValueError as e:
        f.append(Finding(CAT, "Port check skipped", "info", str(e)))
        return res

    with ThreadPoolExecutor(max_workers=13) as ex:
        open_ports = [p for p in ex.map(_probe, [(ip, p) for p in PORTS]) if p]
    res.data["open_ports"] = open_ports

    note = (" The address belongs to a CDN/proxy, so this reflects the CDN edge, not your origin server;"
            " scan your origin IP separately.") if cdn else ""
    if not open_ports:
        f.append(Finding(CAT, "None of the checked risky ports are open", "pass",
                         f"Checked {len(PORTS)} well-known ports on {ip}." + note))
    for p in open_ports:
        svc, sev, advice = PORTS[p]
        if cdn and p not in (8080,):
            sev = "info"
        f.append(Finding(CAT, f"Port {p} open: {svc}", sev,
                         f"{ip}:{p} accepted a TCP connection from the internet." + note, advice))
    return res
