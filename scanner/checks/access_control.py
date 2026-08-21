from urllib.parse import urlparse

from core.baseline import get_soft_404_baseline, is_soft_404
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

ADMIN_LIKE_HINTS = ("admin",)


def check_broken_access_control(low_priv_client: HttpClient, candidate_urls: list[str]) -> list[Finding]:
    """Dusuk yetkili (admin olmayan) bir oturumla, admin'e ozel olmasi beklenen
    URL'lere erisilip erisilemedigini dener -- en net broken-access-control kaniti."""
    findings = []
    seen = set()
    baselines: dict[str, tuple] = {}  # origin -> soft-404 baseline (bkz. core/baseline.py)

    for url in candidate_urls:
        if url in seen or not any(hint in url.lower() for hint in ADMIN_LIKE_HINTS):
            continue
        seen.add(url)

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in baselines:
            baselines[origin] = get_soft_404_baseline(low_priv_client, origin)

        try:
            resp = low_priv_client.get(url, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        if is_soft_404(resp, baselines[origin]):
            # SPA catch-all / ozel hata sayfasi HER path'e (yetkisiz olsa da) ayni 200'u
            # donuyor olabilir -- bu gercek bir erisim kaniti degil, bkz. sensitive_files.py.
            continue

        findings.append(
            Finding(
                title="Broken Access Control (Rol Kontrolü Eksik)",
                severity=Severity.CRITICAL,
                category=Category.WEB,
                location=url,
                description="Yetkisiz (admin olmayan) bir kullanici oturumuyla, admin'e ozel olmasi beklenen bir kaynaga HTTP 200 ile erisildi.",
                evidence=f"Düşük yetkili oturumla GET {url} -> HTTP {resp.status_code}.",
                remediation="Sunucu tarafinda her istekte kullanicinin rolunu/yetkisini dogrulayin (ör. bir @role_required('admin') decorator'i); sadece oturum acmis olmayi yeterli gormeyin.",
            )
        )
    return findings
