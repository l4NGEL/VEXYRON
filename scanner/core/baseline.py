import hashlib
import uuid

from core.http_client import HttpClient


def get_soft_404_baseline(client: HttpClient, base_url: str):
    """SPA catch-all / ozel hata sayfasi gibi, var olmayan HERHANGI bir path'e ayni
    HTTP 200 + ayni govdeyi donen uygulamalari tespit etmek icin, bilerek var olmayan
    rastgele bir path'e istek atip (status_code, content_hash) referansi doner.
    Sonraki '<path> 200 dondu -> bulgu' kontrolleri bu referansla karsilastirilarak
    yanlis pozitifler elenir. Normal (SPA olmayan) bir uygulamada bu baseline zaten
    404 doner, bu yuzden gercek bulgulari etkilemez."""
    probe_path = f"/pentestlab-nonexistent-{uuid.uuid4().hex[:12]}"
    try:
        resp = client.get(base_url.rstrip("/") + probe_path, allow_redirects=False)
        return resp.status_code, hashlib.sha256(resp.content).hexdigest()
    except Exception:
        return None, None


def is_soft_404(resp, baseline) -> bool:
    """resp, get_soft_404_baseline'in dondurdugu (var-olmayan-path) yanitiyla ayni
    status + ayni icerikse True doner -- yani bu path de aslinda 'yok', uygulama
    sadece her bilinmeyen path'e ayni sayfayi (200 ile) donuyor demektir."""
    baseline_status, baseline_hash = baseline
    if baseline_status is None:
        return False
    return resp.status_code == baseline_status and hashlib.sha256(resp.content).hexdigest() == baseline_hash
