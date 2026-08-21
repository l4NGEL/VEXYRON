import re

from core.crawler import Page
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

ID_PATTERN = re.compile(r"^(.*/)(\d+)/?$")


def check_idor(client: HttpClient, pages: list[Page]) -> list[Finding]:
    """Kesfedilen sayfa/link'ler arasinda /kaynak/<sayisal-id> seklindeki URL'leri bulur
    ve komsu id'leri deneyerek sahiplik kontrolu olup olmadigini test eder."""
    findings = []
    seen_prefixes = set()

    candidate_urls = set()
    for page in pages:
        if ID_PATTERN.match(page.url):
            candidate_urls.add(page.url)
        for link in page.links:
            if ID_PATTERN.match(link):
                candidate_urls.add(link)

    for url in candidate_urls:
        match = ID_PATTERN.match(url)
        prefix, id_str = match.group(1), match.group(2)
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

        current_id = int(id_str)
        try:
            baseline = client.get(url)
        except Exception:
            continue
        if baseline.status_code != 200:
            continue

        for probe_id in sorted({current_id - 1, current_id + 1, 1, 2, 3}):
            if probe_id == current_id or probe_id < 1:
                continue
            probe_url = f"{prefix}{probe_id}"
            try:
                probe_resp = client.get(probe_url)
            except Exception:
                continue
            if probe_resp.status_code == 200 and probe_resp.text != baseline.text:
                findings.append(
                    Finding(
                        title="IDOR (Insecure Direct Object Reference)",
                        severity=Severity.HIGH,
                        category=Category.WEB,
                        location=f"{prefix}<id>",
                        description="URL'deki id degistirilerek, sahiplik/yetki kontrolu olmadan baska bir kullaniciya ait veri goruntulenebiliyor.",
                        evidence=f"{url} icin acilan oturumla {probe_url} istendi -> HTTP {probe_resp.status_code}, farkli ve gecerli gorunen icerik dondu.",
                        remediation="Sunucu tarafinda, istegi yapan oturumun ilgili kaynagin gercek sahibi (veya yetkili rolu) oldugunu her istekte dogrulayin.",
                    )
                )
                break
    return findings
