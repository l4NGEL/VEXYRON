from core.auth import build_login_body, find_token
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
    ("root", "root"),
)

# SQLi ile auth bypass denemeleri icin: gercek bir sifre bilmeden, sadece bu payload'larla
# giris denenir. Basarili olursa (redirect / gecerli token donerse) SQLi'nin auth'u
# tamamen atlattigi kanitlanir.
SQLI_BYPASS_PAYLOADS = ("' OR '1'='1' -- ", "' OR '1'='1", "admin' -- ", "' OR 1=1 -- ")


def _looks_successful(resp, as_json: bool) -> bool:
    """Form-tabanli (cookie/redirect) ve JSON-tabanli (JWT) login'lerde basari farkli
    gorunur: birincisinde 3xx redirect, ikincisinde 200 + yanitta bir bearer token."""
    if resp.status_code in (301, 302, 303, 307, 308):
        return True
    if as_json and resp.status_code == 200:
        try:
            return bool(find_token(resp.json()))
        except ValueError:
            return False
    return False


def check_auth_weakness(
    client: HttpClient,
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    as_json: bool = False,
    extra_fields: dict = None,
) -> list[Finding]:
    findings = []

    def _post(user, pwd):
        body = build_login_body(username_field, user, pwd, extra_fields)
        body[password_field] = body.pop("password")  # password alan adi da ozellestirilebilir
        if as_json:
            return client.post(login_url, json=body, allow_redirects=False)
        return client.post(login_url, data=body, allow_redirects=False)

    # 1) Rate limiting testi: ayni yanlis bilgilerle art arda N deneme
    attempts = 8
    blocked = False
    last_status = None
    for i in range(attempts):
        try:
            resp = _post("pentestlab_ratelimit_probe", f"wrong{i}")
        except Exception:
            break
        last_status = resp.status_code
        if resp.status_code in (403, 429):
            blocked = True
            break

    if not blocked and last_status is not None:
        findings.append(
            Finding(
                title="Rate Limiting / Hesap Kilitleme Yok",
                severity=Severity.HIGH,
                category=Category.WEB,
                location=login_url,
                description=f"{attempts} ardisik basarisiz login denemesi hicbir sekilde engellenmedi veya yavaslatilmadi; brute-force saldirisina acik.",
                evidence=f"{attempts} deneme sonunda son HTTP durumu: {last_status} (403/429 gibi bir engelleme kodu gorulmedi).",
                remediation="Basarisiz denemeler icin rate limiting / progressive delay / hesap kilitleme ekleyin (ör. Flask-Limiter).",
            )
        )

    # 2) Yaygin varsayilan/zayif kimlik bilgisi denemesi
    for user, pwd in DEFAULT_CREDENTIALS:
        try:
            resp = _post(user, pwd)
        except Exception:
            continue
        if _looks_successful(resp, as_json):
            findings.append(
                Finding(
                    title="Zayıf/Varsayılan Kimlik Bilgisi",
                    severity=Severity.CRITICAL,
                    category=Category.WEB,
                    location=login_url,
                    description="Yaygin bir varsayilan kullanici adi/sifre kombinasyonuyla giris basarili oldu.",
                    evidence=f"{user}/{pwd} ile POST {login_url} -> HTTP {resp.status_code}, basarili giris kaniti bulundu.",
                    remediation="Varsayilan/zayif sifreleri yasaklayin, ilk kurulumda guclu sifre belirlemeyi zorunlu kilin.",
                )
            )
            break

    # 3) SQLi ile auth bypass denemesi: gercek bir sifre olmadan sadece payload ile giris
    for payload in SQLI_BYPASS_PAYLOADS:
        try:
            resp = _post(payload, "definitely_wrong_password_xyz")
        except Exception:
            continue
        if _looks_successful(resp, as_json):
            findings.append(
                Finding(
                    title="SQL Injection ile Auth Bypass",
                    severity=Severity.CRITICAL,
                    category=Category.WEB,
                    location=login_url,
                    description="Bilinen bir sifre olmadan, SQLi payload'i ile kimlik dogrulama tamamen bypass edilebildi.",
                    evidence=f"{username_field}={payload!r} ile POST {login_url} -> HTTP {resp.status_code}, basarili giris kaniti bulundu.",
                    remediation="Parametreli sorgular kullanin; sifre karsilastirmasini SQL icinde degil uygulama katmaninda (hash ile) yapin.",
                )
            )
            break
    return findings
