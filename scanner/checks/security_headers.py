from core.crawler import Page
from core.models import Category, Finding, Severity

EXPECTED_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", Severity.MEDIUM),
    "x-frame-options": ("X-Frame-Options", Severity.MEDIUM),
    "x-content-type-options": ("X-Content-Type-Options", Severity.LOW),
    "strict-transport-security": ("Strict-Transport-Security", Severity.LOW),
}

_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def check_security_headers(pages: list[Page]) -> list[Finding]:
    if not pages:
        return []

    # Header seti site genelinde genelde ayni oldugundan bir kez raporlamak yeterli.
    sample = pages[0]
    lower_headers = {k.lower(): v for k, v in sample.headers.items()}

    missing = [display for key, (display, _sev) in EXPECTED_HEADERS.items() if key not in lower_headers]
    if not missing:
        return []

    worst = min((EXPECTED_HEADERS[m.lower()][1] for m in missing), key=lambda s: _SEVERITY_RANK[s])
    return [
        Finding(
            title="Eksik Güvenlik Header'ları",
            severity=worst,
            category=Category.WEB,
            location=sample.url,
            description="Yanitlarda tarayici tabanli saldirilara (clickjacking, MIME sniffing, protokol downgrade) karsi koruyucu header'lar eksik.",
            evidence=f"Eksik header'lar: {', '.join(missing)}",
            remediation="Flask-Talisman gibi bir kutuphane veya after_request hook'uyla CSP/X-Frame-Options/X-Content-Type-Options/HSTS header'larini ekleyin.",
        )
    ]


def check_cookie_flags(set_cookie_header: str, location: str) -> list[Finding]:
    """Set-Cookie header'i genelde sadece oturumun KURULDUGU (ör. login) response'ta
    gorunur, sonraki her sayfada tekrar gonderilmez -- bu yuzden bu kontrol crawl'daki
    rastgele bir sayfa yerine, cagiran taraf hangi response'ta cookie'yi yakaladiysa
    ona (ör. login response'u) uygulanmalidir."""
    if not set_cookie_header:
        return []

    findings = []
    lowered = set_cookie_header.lower()
    if "httponly" not in lowered:
        findings.append(
            Finding(
                title="Cookie HttpOnly Bayrağı Eksik",
                severity=Severity.MEDIUM,
                category=Category.WEB,
                location=location,
                description="Session cookie HttpOnly olarak isaretlenmemis; bir XSS acigi varsa JavaScript ile okunup calinabilir.",
                evidence=f"Set-Cookie: {set_cookie_header}",
                remediation="Flask'ta SESSION_COOKIE_HTTPONLY=True ayarlayin.",
            )
        )
    if "secure" not in lowered:
        findings.append(
            Finding(
                title="Cookie Secure Bayrağı Eksik",
                severity=Severity.LOW,
                category=Category.WEB,
                location=location,
                description="Session cookie Secure olarak isaretlenmemis; HTTPS disi (duz metin) baglantida da gonderilebilir.",
                evidence=f"Set-Cookie: {set_cookie_header}",
                remediation="Prod ortaminda SESSION_COOKIE_SECURE=True ayarlayip HTTPS'i zorunlu kilin.",
            )
        )
    return findings
