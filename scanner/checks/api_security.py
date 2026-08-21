from core.baseline import get_soft_404_baseline, is_soft_404
from core.http_client import HttpClient
from core.models import Category, Finding, Severity
from checks.sqli import DB_ERROR_SIGNATURES, PAYLOADS as SQLI_PAYLOADS

COMMON_API_PATHS = (
    "/login",
    "/auth/login",
    "/session",
    "/users",
    "/user",
    "/profile",
    "/admin/users",
    "/admin",
    "/search",
    "/products",
    "/health",
    "/status",
    "/me",
    "/register",
)

ID_CAPABLE_PATHS = ("/profile", "/users", "/user", "/products", "/orders", "/items")

AUTH_BYPASS_PAYLOADS = ("' OR '1'='1' -- ", "' OR '1'='1", "admin' -- ", "' OR 1=1 -- ")

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pwd",
    "password_hash",
    "secret",
    "token",
    "api_key",
    "apikey",
    "ssn",
    "credit_card",
    "card_number",
    "notes",
    "internal_notes",
    "private_key",
}


def discover_api_endpoints(client: HttpClient, api_base: str, openapi_path: str = None) -> list[dict]:
    """OpenAPI spec (verilirse) + yaygin REST path wordlist'i + sayisal id brute-force ile
    JSON API endpoint'lerini kesfeder. HTML sayfalarin aksine JSON API'ler link ile
    birbirine baglanmadigindan crawling yerine bu yaklasim kullanilir."""
    api_base = api_base.rstrip("/")
    endpoints: list[dict] = []
    seen: set[tuple[str, str]] = set()

    # SPA catch-all / ozel hata sayfasi olan uygulamalar HER path'e (var olmayanlar
    # dahil) ayni HTTP 200'u dondurebilir -- bu, naif "200/404-degil = endpoint var"
    # mantiginda onlarca hayali endpoint "kesfedilmesine" yol acar. Referans alip
    # gercek adaylari bununla karsilastiriyoruz.
    baseline = get_soft_404_baseline(client, api_base)

    def add(url, method, template, **extra):
        key = (url, method)
        if key in seen:
            return
        seen.add(key)
        entry = {"url": url, "method": method, "template": template}
        entry.update(extra)
        endpoints.append(entry)

    if openapi_path:
        try:
            import json as _json

            with open(openapi_path, "r", encoding="utf-8") as fh:
                spec = _json.load(fh)
            for path, methods in spec.get("paths", {}).items():
                for method in methods:
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        add(api_base + path, method.upper(), path)
        except Exception:
            pass

    for path in COMMON_API_PATHS:
        url = api_base + path
        try:
            resp = client.get(url)
        except Exception:
            continue
        if resp.status_code == 404 or is_soft_404(resp, baseline):
            continue
        add(url, "GET", path)
        # 405 (Method Not Allowed) POST-only bir route'un var oldugunu gosterir.
        if any(h in path.lower() for h in ("login", "auth", "session")):
            add(url, "POST", path)

    for path in ID_CAPABLE_PATHS:
        for i in range(1, 6):
            url = f"{api_base}{path}/{i}"
            try:
                resp = client.get(url)
            except Exception:
                continue
            if resp.status_code != 404 and not is_soft_404(resp, baseline):
                add(url, "GET", f"{path}/<id>", id=i)

    return endpoints


def _login_endpoints(endpoints: list[dict]) -> list[dict]:
    return [
        e
        for e in endpoints
        if e["method"] == "POST" and any(h in e["template"].lower() for h in ("login", "auth", "session"))
    ]


def check_api_auth_bypass_sqli(client: HttpClient, endpoints: list[dict]) -> list[Finding]:
    findings = []
    for ep in _login_endpoints(endpoints):
        for payload in AUTH_BYPASS_PAYLOADS:
            try:
                resp = client.post(
                    ep["url"], json={"username": payload, "password": "definitely_wrong_password_xyz"}
                )
            except Exception:
                continue
            success_signal = resp.status_code == 200 and any(
                marker in resp.text.lower() for marker in ('"ok"', "user_id", "token")
            )
            if success_signal:
                findings.append(
                    Finding(
                        title="SQL Injection ile Auth Bypass (JSON API)",
                        severity=Severity.CRITICAL,
                        category=Category.API,
                        location=f"POST {ep['url']}",
                        description="Gercek bir sifre bilinmeden, SQLi payload'i ile JSON API kimlik dogrulamasi bypass edilebildi.",
                        evidence=f"Body: {{'username': {payload!r}, 'password': 'definitely_wrong_password_xyz'}} -> HTTP {resp.status_code}, basarili giris yaniti.",
                        remediation="Parametreli sorgular kullanin; sifre karsilastirmasini SQL icinde degil uygulama katmaninda (hash ile) yapin.",
                    )
                )
                break
    return findings


def check_api_sqli(client: HttpClient, endpoints: list[dict]) -> list[Finding]:
    findings = []
    tested_urls = set()
    for ep in endpoints:
        if ep["method"] != "POST" or ep["url"] in tested_urls:
            continue
        tested_urls.add(ep["url"])
        for payload in SQLI_PAYLOADS:
            body = {"username": payload, "password": payload, "q": payload, "search": payload}
            try:
                resp = client.post(ep["url"], json=body)
            except Exception:
                continue
            lowered = resp.text.lower()
            if any(sig in lowered for sig in DB_ERROR_SIGNATURES):
                findings.append(
                    Finding(
                        title="SQL Injection (JSON API)",
                        severity=Severity.CRITICAL,
                        category=Category.API,
                        location=f"POST {ep['url']}",
                        description="JSON govdesindeki bir alana gonderilen payload veritabani hatasi tetikledi.",
                        evidence=f"Payload: {payload!r} -> yanitta DB hata imzasi bulundu.",
                        remediation="Parametreli sorgular kullanin; JSON govdesinden gelen degerleri de SQL string'ine dogrudan gommeyin.",
                    )
                )
                break
    return findings


def check_bola(client: HttpClient, endpoints: list[dict]) -> list[Finding]:
    findings = []
    by_template: dict[str, list[dict]] = {}
    for e in endpoints:
        if e["method"] == "GET" and "id" in e:
            by_template.setdefault(e["template"], []).append(e)

    for template, eps in by_template.items():
        eps_sorted = sorted(eps, key=lambda e: e["id"])
        if len(eps_sorted) < 2:
            continue
        base = eps_sorted[0]
        try:
            base_resp = client.get(base["url"])
        except Exception:
            continue
        if base_resp.status_code != 200:
            continue
        for other in eps_sorted[1:]:
            try:
                other_resp = client.get(other["url"])
            except Exception:
                continue
            if other_resp.status_code == 200 and other_resp.text != base_resp.text:
                findings.append(
                    Finding(
                        title="BOLA / IDOR (JSON API)",
                        severity=Severity.HIGH,
                        category=Category.API,
                        location=f"GET {template}",
                        description="API, istegi yapan kullanicinin ilgili kaydin sahibi olup olmadigini kontrol etmeden farkli id'ler icin veri donduruyor.",
                        evidence=f"{base['url']} ve {other['url']} ayni oturumla istendi, ikisi de HTTP 200 dondu ve icerikleri farkli/gecerli.",
                        remediation="Her istekte oturumdaki kullanicinin istenen kaynagin sahibi (veya yetkili rolu) oldugunu sunucu tarafinda dogrulayin (object-level authorization).",
                    )
                )
                break
    return findings


def check_excessive_data_exposure(client: HttpClient, endpoints: list[dict]) -> list[Finding]:
    findings = []
    seen_templates = set()
    for ep in endpoints:
        if ep["method"] != "GET" or ep["template"] in seen_templates:
            continue
        try:
            resp = client.get(ep["url"])
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        seen_templates.add(ep["template"])

        records = data if isinstance(data, list) else [data]
        exposed = set()
        for record in records:
            if isinstance(record, dict):
                for key in record:
                    if key.lower() in SENSITIVE_FIELD_NAMES:
                        exposed.add(key)
        if exposed:
            findings.append(
                Finding(
                    title="Excessive Data Exposure (API)",
                    severity=Severity.HIGH,
                    category=Category.API,
                    location=f"GET {ep['url']}",
                    description="API yaniti, istemcinin (mobil uygulamanin) normalde ihtiyaci olmayan hassas alanlari da iceriyor.",
                    evidence=f"Yanitta bulunan hassas alan adlari: {sorted(exposed)}",
                    remediation="API yanit semasini istemcinin gercekten ihtiyaci oldugu alanlarla sinirlayin (DTO/serializer whitelist), hassas alanlari sunucu tarafinda filtreleyin.",
                )
            )
    return findings


def check_api_auth_weakness(client: HttpClient, endpoints: list[dict]) -> list[Finding]:
    findings = []
    login_eps = _login_endpoints(endpoints)
    if not login_eps:
        return findings

    ep = login_eps[0]
    attempts = 8
    blocked = False
    last_status = None
    for i in range(attempts):
        try:
            resp = client.post(ep["url"], json={"username": "pentestlab_ratelimit_probe", "password": f"wrong{i}"})
        except Exception:
            break
        last_status = resp.status_code
        if resp.status_code in (403, 429):
            blocked = True
            break

    if not blocked and last_status is not None:
        findings.append(
            Finding(
                title="Rate Limiting Yok (API)",
                severity=Severity.HIGH,
                category=Category.API,
                location=f"POST {ep['url']}",
                description=f"{attempts} ardisik basarisiz API login denemesi engellenmedi; brute-force'a acik.",
                evidence=f"{attempts} deneme sonunda son HTTP durumu: {last_status} (403/429 gorulmedi).",
                remediation="API login endpoint'ine IP/kullanici bazli rate limiting ekleyin.",
            )
        )
    return findings


def run_api_checks(client: HttpClient, api_base: str, openapi_path: str = None) -> list[Finding]:
    endpoints = discover_api_endpoints(client, api_base, openapi_path)

    findings: list[Finding] = []
    findings += check_api_auth_bypass_sqli(client, endpoints)
    findings += check_api_sqli(client, endpoints)
    findings += check_bola(client, endpoints)
    findings += check_excessive_data_exposure(client, endpoints)
    findings += check_api_auth_weakness(client, endpoints)
    return findings
