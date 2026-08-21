import uuid

from core.crawler import Page
from core.http_client import HttpClient
from core.models import Category, Finding, Severity


def check_xss(client: HttpClient, pages: list[Page]) -> list[Finding]:
    findings = []
    tested = set()

    for page in pages:
        for form in page.forms:
            input_names = tuple(i["name"] for i in form["inputs"])
            key = (form["action"], form["method"], input_names)
            if key in tested or not input_names:
                continue
            tested.add(key)

            token = uuid.uuid4().hex[:8]
            payload = f"<script>/*PENTESTLAB_XSS_{token}*/</script>"
            data = {inp["name"]: payload for inp in form["inputs"] if inp["type"] != "submit"}
            if not data:
                continue

            try:
                if form["method"] == "post":
                    resp = client.post(form["action"], data=data)
                else:
                    resp = client.get(form["action"], params=data)
            except Exception:
                continue

            found_in = None
            if payload in resp.text:
                found_in = "reflected (istegin dogrudan yanitinda)"
            else:
                # stored XSS ihtimali: ayni sayfayi tekrar GET ile cek
                try:
                    verify_url = form["action"] if form["method"] == "get" else page.url
                    verify_resp = client.get(verify_url)
                    if payload in verify_resp.text:
                        found_in = "stored (sonraki GET isteginde kalici olarak bulundu)"
                except Exception:
                    pass

            if found_in:
                findings.append(
                    Finding(
                        title="Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        category=Category.WEB,
                        location=f"{form['method'].upper()} {form['action']}",
                        description=f"Enjekte edilen <script> payload'i escape edilmeden HTML yanitina yansidi -- {found_in}.",
                        evidence=f"Payload: {payload!r} yanitta degistirilmeden (escape edilmeden) bulundu.",
                        remediation="Kullanici girdisini render etmeden once HTML-escape edin; template motorunun otomatik escaping'ini (ör. Jinja2 |safe) gereksiz yere devre disi birakmayin.",
                    )
                )
    return findings
