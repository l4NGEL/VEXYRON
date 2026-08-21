"""Veritabani servislerinin disari acik / kimlik dogrulamasiz maruziyet kontrolleri.

Sifre kirma, exploit veya dump yok. Yalniz TCP baglantisi, protokol selamlama
ve (Redis/Memcached/Elasticsearch icin) AUTH gerekip gerekmedigini anlayan
zararsiz bir komut. Hedef safety.assert_authorized ile zaten sinirlanir.
"""

from __future__ import annotations

import socket

from core.baseline import get_soft_404_baseline, is_soft_404
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

DB_PORTS = {
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

SQLITE_PATHS = (
    "/app.db",
    "/data.db",
    "/database.sqlite",
    "/database.sqlite3",
    "/db.sqlite3",
    "/dump.sql",
    "/backup.sql",
)


def _recv(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except (socket.timeout, OSError):
        return b""


def _connect(host: str, port: int, timeout: float) -> socket.socket | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _exposed_service(host: str, port: int, service: str, banner: str) -> Finding:
    evidence = f"TCP connect basarili, {service} {host}:{port} dinliyor."
    if banner:
        evidence += f" Banner: {banner[:120]!r}"
    return Finding(
        title=f"Disari acik veritabani servisi: {service}",
        severity=Severity.HIGH,
        category=Category.DATABASE,
        location=f"{host}:{port}",
        description=(
            f"{service} internete/ag'a acik. Dogrudan veri tabani erisimi brute-force, "
            "varsayilan sifre ve yanlis yapilandirma riskini buyutur."
        ),
        evidence=evidence,
        remediation=(
            "Bu portu disari kapatın, yalniz uygulama sunucusunun ulasabilecegi bir "
            "ic ag/firewall kurali koyun; sifreleme ve zorunlu kimlik dogrulama acik olsun."
        ),
    )


def _check_redis(host: str, timeout: float) -> list[Finding]:
    sock = _connect(host, 6379, timeout)
    if sock is None:
        return []
    findings = []
    try:
        sock.sendall(b"PING\r\n")
        data = _recv(sock, 64, timeout)
        text = data.decode("latin-1", errors="ignore")
        if "+PONG" in text:
            findings.append(
                Finding(
                    title="Redis kimlik dogrulamasiz erisilebilir",
                    severity=Severity.CRITICAL,
                    category=Category.DATABASE,
                    location=f"{host}:6379",
                    description=(
                        "Redis PING'e AUTH olmadan PONG dondurdu. Kimlik dogrulamasiz "
                        "Redis uzerinden veri okuma/yazma ve bazen host komutu mumkundur."
                    ),
                    evidence=f"PING -> {text.strip()[:80]!r}",
                    remediation="requirepass veya ACL acin; portu localhost/ic ag ile sinirlayin; protected-mode yes kalsin.",
                )
            )
        else:
            banner = text.strip()
            findings.append(_exposed_service(host, 6379, "Redis", banner))
    except OSError:
        pass
    finally:
        sock.close()
    return findings


def _check_memcached(host: str, timeout: float) -> list[Finding]:
    sock = _connect(host, 11211, timeout)
    if sock is None:
        return []
    findings = []
    try:
        sock.sendall(b"stats\r\n")
        data = _recv(sock, 256, timeout)
        text = data.decode("latin-1", errors="ignore")
        if "STAT " in text:
            findings.append(
                Finding(
                    title="Memcached kimlik dogrulamasiz erisilebilir",
                    severity=Severity.HIGH,
                    category=Category.DATABASE,
                    location=f"{host}:11211",
                    description="Memcached STATS komutunu AUTH olmadan yanitladi; onbellekteki veri sizabilir.",
                    evidence=f"stats -> {text.strip()[:100]!r}",
                    remediation="Memcached'i yalniz localhost'a baglayin; SASL acin; 11211'i firewall ile kapatın.",
                )
            )
        else:
            findings.append(_exposed_service(host, 11211, "Memcached", text.strip()))
    except OSError:
        pass
    finally:
        sock.close()
    return findings


def _check_elasticsearch(client: HttpClient, host: str) -> list[Finding]:
    url = f"http://{host}:9200/"
    try:
        resp = client.get(url, allow_redirects=False)
    except Exception:
        return []
    if resp.status_code != 200:
        return []
    body = (resp.text or "")[:800]
    if "cluster_name" in body or "You Know, for Search" in body or '"tagline"' in body:
        return [
            Finding(
                title="Elasticsearch kimlik dogrulamasiz HTTP API",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                location=url,
                description="Elasticsearch kok endpoint'i AUTH olmadan 200 dondurdu; indeksler okunabilir/degistirilebilir olabilir.",
                evidence=f"GET {url} -> {resp.status_code}, govde: {body[:160]!r}",
                remediation="xpack.security.enabled acin; HTTP portunu ic aga alin; reverse proxy ile kimlik dogrulama koyun.",
            )
        ]
    return []


def _banner_service(host: str, port: int, service: str, timeout: float) -> list[Finding]:
    sock = _connect(host, port, timeout)
    if sock is None:
        return []
    try:
        banner = _recv(sock, 160, timeout).decode("latin-1", errors="ignore").strip()
    except OSError:
        banner = ""
    finally:
        sock.close()
    return [_exposed_service(host, port, service, banner)]


def _check_sqlite_paths(client: HttpClient, base_url: str) -> list[Finding]:
    findings = []
    base = base_url.rstrip("/")
    baseline = get_soft_404_baseline(client, base)
    for path in SQLITE_PATHS:
        url = base + path
        try:
            resp = client.get(url, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 200 or is_soft_404(resp, baseline):
            continue
        content = resp.content[:16]
        looks_sqlite = content.startswith(b"SQLite format 3")
        looks_sql = path.endswith(".sql") and (
            b"INSERT " in resp.content[:4000].upper()
            or b"CREATE " in resp.content[:4000].upper()
            or b"--" in content
        )
        if not (looks_sqlite or looks_sql):
            continue
        findings.append(
            Finding(
                title="Veritabani dosyasi HTTP ile indirilebilir",
                severity=Severity.CRITICAL,
                category=Category.DATABASE,
                location=url,
                description=f"'{path}' web kokunden 200 donuyor; SQLite/SQL dump herkese acik olabilir.",
                evidence=f"GET {url} -> {resp.status_code}, {len(resp.content)} byte, magik={content[:12]!r}",
                remediation="DB dosyalarini web root disina tasiyin; statik sunucuda .db/.sqlite/.sql uzantilarini yasaklayin.",
            )
        )
    return findings


def check_database(host: str, client: HttpClient | None = None, web_url: str | None = None, timeout: float = 0.8) -> list[Finding]:
    """host uzerindeki yaygin DB portlarini ve (web_url varsa) SQLite/dump path'lerini tarar."""
    findings: list[Finding] = []
    if host:
        findings += _check_redis(host, timeout)
        findings += _check_memcached(host, timeout)
        for port, service in DB_PORTS.items():
            if port in (6379, 11211, 9200):
                continue
            findings += _banner_service(host, port, service, timeout)
        if client is not None:
            findings += _check_elasticsearch(client, host)
    if client is not None and web_url:
        findings += _check_sqlite_paths(client, web_url)
    return findings
