from core.baseline import get_soft_404_baseline, is_soft_404
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

SENSITIVE_PATHS = {
    "/.env": Severity.CRITICAL,
    "/.git/config": Severity.HIGH,
    "/config_backup.txt": Severity.HIGH,
    "/static/config_backup.txt": Severity.HIGH,
    "/backup.zip": Severity.MEDIUM,
    "/backup.sql": Severity.CRITICAL,
    "/uploads/": Severity.MEDIUM,
    "/static/uploads/": Severity.MEDIUM,
    "/.DS_Store": Severity.LOW,
    "/web.config": Severity.MEDIUM,
    "/wp-config.php.bak": Severity.HIGH,
    "/server-status": Severity.MEDIUM,
    "/phpinfo.php": Severity.HIGH,
    "/.well-known/security.txt": Severity.INFO,
}


def check_sensitive_files(client: HttpClient, base_url: str) -> list[Finding]:
    findings = []
    base = base_url.rstrip("/")
    # SPA catch-all / ozel hata sayfasi olan uygulamalar HER path'e (var olmayanlar
    # dahil) ayni HTTP 200'u dondurebilir -- bu, naif "200 = bulgu" mantiginda toplu
    # yanlis pozitif uretir. Once bilerek var olmayan bir path'in yanitini referans
    # alip, gercek adaylari bununla karsilastiriyoruz.
    baseline = get_soft_404_baseline(client, base)

    for path, severity in SENSITIVE_PATHS.items():
        url = base + path
        try:
            resp = client.get(url, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        if is_soft_404(resp, baseline):
            continue
        findings.append(
            Finding(
                title="Hassas Dosya/Path Erişilebilir",
                severity=severity,
                category=Category.WEB,
                location=url,
                description=f"'{path}' path'i HTTP 200 dondurdu; normalde herkese acik olmamasi gereken bir kaynak olabilir.",
                evidence=f"GET {url} -> {resp.status_code}, {len(resp.content)} byte yanit.",
                remediation="Bu dosyayi web root disina tasiyin veya web sunucusu/uygulama seviyesinde disaridan erisimi engelleyin.",
            )
        )
    return findings
