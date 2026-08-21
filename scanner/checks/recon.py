"""Aktif/pasif keşif — pentest'in Reconnaissance / Information Gathering asaması.

WHOIS ve DNS hedefe saldiri degildir; dizin kesfi ve parmak izi yalniz
assert_authorized gecmis hedefte, kisa bir wordlist ve soft-404 filtresiyle yapilir.
Exploit, payload, phishing yok.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from core.baseline import get_soft_404_baseline, is_soft_404
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

DIR_WORDLIST = (
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/login",
    "/api",
    "/api/docs",
    "/swagger",
    "/swagger-ui",
    "/graphql",
    "/health",
    "/actuator",
    "/phpmyadmin",
    "/.git/HEAD",
    "/server-status",
    "/wp-admin",
    "/console",
)

TECH_HINTS = (
    ("cloudflare", "Cloudflare"),
    ("nginx", "nginx"),
    ("apache", "Apache"),
    ("gunicorn", "Gunicorn"),
    ("werkzeug", "Werkzeug/Flask"),
    ("express", "Express"),
    ("php/", "PHP"),
    ("asp.net", "ASP.NET"),
    ("iis", "IIS"),
    ("litespeed", "LiteSpeed"),
)

HTML_HINTS = (
    ("wp-content", "WordPress"),
    ("__NEXT_DATA__", "Next.js"),
    ("react", "React"),
    ("ng-version", "Angular"),
    ("cdn.jsdelivr.net/npm/vue", "Vue"),
    ("jquery", "jQuery"),
    ("django", "Django"),
    ("flask", "Flask"),
    ("csrfmiddlewaretoken", "Django CSRF"),
)


def _is_public_host(host: str) -> bool:
    if not host or host.lower() in {"localhost", "::1"}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except (socket.gaierror, OSError, ValueError):
            return False


def _dns_summary(host: str) -> str:
    lines = []
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({item[4][0] for item in infos})
        if addrs:
            lines.append("A/AAAA: " + ", ".join(addrs[:8]))
    except (socket.gaierror, OSError):
        lines.append("A/AAAA: cozulemedi")
    try:
        fqdn = socket.getfqdn(host)
        if fqdn and fqdn != host:
            lines.append(f"FQDN: {fqdn}")
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(host)
        ptr = socket.gethostbyaddr(ip)[0]
        if ptr:
            lines.append(f"PTR: {ptr}")
    except (socket.gaierror, socket.herror, OSError):
        pass
    return "\n".join(lines) if lines else "DNS kaydi alinamadi"


def _whois_query(query: str, server: str, timeout: float = 4.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(query.encode("ascii", "ignore") + b"\r\n")
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 20000:
                break
    return b"".join(chunks).decode("utf-8", "replace")


def _whois_brief(host: str) -> str:
    if not _is_public_host(host):
        return ""
    domain = host
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        domain = host
    try:
        iana = _whois_query(domain, "whois.iana.org")
        refer = ""
        for line in iana.splitlines():
            if line.lower().startswith("refer:") or line.lower().startswith("whois:"):
                refer = line.split(":", 1)[1].strip()
                if refer:
                    break
        server = refer or "whois.iana.org"
        raw = _whois_query(domain, server) if refer else iana
    except (OSError, socket.timeout):
        return ""
    keep = []
    for line in raw.splitlines():
        key = line.split(":", 1)[0].strip().lower()
        if key in {
            "registrar",
            "orgname",
            "org-name",
            "netname",
            "country",
            "nserver",
            "name server",
            "creation date",
            "created",
            "org",
        }:
            keep.append(line.strip())
        if len(keep) >= 8:
            break
    return "\n".join(keep)


def _fingerprint(page) -> list[str]:
    found = []
    headers = {k.lower(): v for k, v in (page.headers or {}).items()}
    blob = " ".join(
        [
            headers.get("server", ""),
            headers.get("x-powered-by", ""),
            headers.get("via", ""),
            headers.get("x-generator", ""),
        ]
    ).lower()
    for needle, label in TECH_HINTS:
        if needle in blob and label not in found:
            found.append(label)
    html = (page.html or "").lower()
    for needle, label in HTML_HINTS:
        if needle.lower() in html and label not in found:
            found.append(label)
    if headers.get("server") and headers["server"] not in found:
        found.insert(0, f"Server={headers['server']}")
    if headers.get("x-powered-by"):
        found.append(f"X-Powered-By={headers['x-powered-by']}")
    return found


def _check_dirs(client: HttpClient, base_url: str) -> list[Finding]:
    findings = []
    base = base_url.rstrip("/")
    baseline = get_soft_404_baseline(client, base)
    live = []
    git_head = False
    for path in DIR_WORDLIST:
        url = base + path
        try:
            resp = client.get(url, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code not in (200, 301, 302, 401, 403):
            continue
        if resp.status_code == 200 and is_soft_404(resp, baseline):
            continue
        live.append(f"{path} ({resp.status_code})")
        if path == "/.git/HEAD" and resp.status_code == 200 and b"ref:" in resp.content[:40]:
            git_head = True
    if live:
        findings.append(
            Finding(
                title="Keşfedilen dizin / uç",
                severity=Severity.INFO,
                category=Category.RECON,
                location=base,
                description="Kisa bir recon wordlist ile yanit veren path'ler. Hassas dosya kontrolleri ayri calisir.",
                evidence="; ".join(live[:20]),
                remediation="Gereksiz admin/docs/debug uclarini kapatın veya kimlik dogrulamasi ekleyin.",
            )
        )
    if git_head:
        findings.append(
            Finding(
                title="Acik .git/HEAD",
                severity=Severity.HIGH,
                category=Category.RECON,
                location=base + "/.git/HEAD",
                description="Git metadata web'den okunuyor; kaynak kod cekilebilir.",
                evidence="GET /.git/HEAD 200 ve 'ref:' magigi",
                remediation=".git dizinini web root disina alin veya sunucuda erisimi kapatın.",
            )
        )
    return findings


def _robots(client: HttpClient, base_url: str) -> list[Finding]:
    url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = client.get(url, allow_redirects=False)
    except Exception:
        return []
    if resp.status_code != 200:
        return []
    text = resp.text or ""
    disallows = [ln.strip() for ln in text.splitlines() if ln.lower().startswith("disallow:")]
    if not disallows:
        return []
    return [
        Finding(
            title="robots.txt icinde gizlenen path'ler",
            severity=Severity.INFO,
            category=Category.RECON,
            location=url,
            description="Disallow kayitlari saldirgana harita verir; gizlilik saglamaz.",
            evidence="\n".join(disallows[:15]),
            remediation="Gizli panelleri robots ile degil kimlik dogrulama ve ag kisiti ile koruyun.",
        )
    ]


def check_recon(client: HttpClient, url: str, pages: list | None = None) -> list[Finding]:
    host = urlparse(url).hostname or ""
    findings: list[Finding] = []

    dns = _dns_summary(host)
    findings.append(
        Finding(
            title="DNS keşfi",
            severity=Severity.INFO,
            category=Category.RECON,
            location=host or url,
            description="Hedef hostname icin A/AAAA ve varsa PTR kayitlari (aktif DNS).",
            evidence=dns,
            remediation="Gereksiz hostname/PTR kayitlarini azaltın; ic sunuculari genel DNS'te yayinlamayin.",
        )
    )

    whois = _whois_brief(host)
    if whois:
        findings.append(
            Finding(
                title="WHOIS ozeti",
                severity=Severity.INFO,
                category=Category.RECON,
                location=host,
                description="Pasif kayit ozeti (IANA/registrar). Localhost ve private IP atlanir.",
                evidence=whois,
                remediation="WHOIS gizliligi kurum politikasina gore; asil risk acik port ve zayif servislerdir.",
            )
        )

    page0 = (pages or [None])[0]
    if page0 is not None:
        tech = _fingerprint(page0)
        if tech:
            findings.append(
                Finding(
                    title="Teknoloji parmak izi",
                    severity=Severity.INFO,
                    category=Category.RECON,
                    location=page0.url,
                    description="Server header, X-Powered-By ve HTML ipuclari. Surum bilgisi exploit degil, yama onceligi icin.",
                    evidence=", ".join(tech[:12]),
                    remediation="Server/X-Powered-By banner'larini azaltın; bilesenleri guncel tutun.",
                )
            )

    findings += _robots(client, url)
    findings += _check_dirs(client, url)
    return findings
