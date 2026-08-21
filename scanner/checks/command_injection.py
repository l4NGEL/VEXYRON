import html

from core.crawler import Page
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

HOST_FIELD_HINTS = ("host", "ip", "addr", "target", "domain")


def _submit(client, form, data):
    if form["method"] == "post":
        return client.post(form["action"], data=data)
    return client.get(form["action"], params=data)


def check_command_injection(client: HttpClient, pages: list[Page]) -> list[Finding]:
    findings = []
    tested = set()

    for page in pages:
        for form in page.forms:
            host_input_names = [i["name"] for i in form["inputs"] if any(h in i["name"].lower() for h in HOST_FIELD_HINTS)]
            if not host_input_names:
                continue
            key = (form["action"], form["method"])
            if key in tested:
                continue
            tested.add(key)

            token = f"PENTESTLABCMDI{abs(hash(form['action'])) % 100000}"
            # && ve | Windows cmd.exe + Unix shell'lerde ortak calisir; ; sadece Unix'te ayirici.
            payloads = [
                f"127.0.0.1 && echo {token}",
                f"127.0.0.1 | echo {token}",
                f"127.0.0.1; echo {token}",
            ]

            for payload in payloads:
                data = {
                    inp["name"]: (payload if inp["name"] in host_input_names else "test")
                    for inp in form["inputs"]
                    if inp["type"] != "submit"
                }
                try:
                    resp = _submit(client, form, data)
                except Exception:
                    continue

                # Kritik ayrim: marker gorunuyor AMA gonderdigimiz payload'in TAMAMI
                # yanitta YOK (ne ham haliyle ne HTML-escape'lenmis haliyle) -- yani
                # sadece "echo <marker>" kisminin CIKTISINI goruyoruz, ham girdinin
                # kendisini degil. Bircok uygulama (ör. bir DNS-cozumleme hata mesaji
                # ("could not find host <girdi>"), ya da bir formu ayni degerle geri
                # dolduran hata sayfasi) girdiyi OLDUGU GIBI yansitir -- boyle
                # durumlarda payload'in TAMAMI da yanitta gorunur (Jinja gibi
                # template motorlari '&' karakterini '&amp;' olarak escape eder,
                # o yuzden hem ham hem escape'li hali kontrol edilir). Bu, gercek
                # komut CALISTIRMASI degil sadece echo/yansitma oldugunu gosterir
                # ve yanlis pozitifi eler.
                payload_reflected = payload in resp.text or html.escape(payload) in resp.text
                if token in resp.text and not payload_reflected:
                    findings.append(
                        Finding(
                            title="OS Command Injection",
                            severity=Severity.CRITICAL,
                            category=Category.WEB,
                            location=f"{form['method'].upper()} {form['action']}",
                            description="Host/IP alanina eklenen shell meta-karakterleri (&&, |, ;) sunucuda calistirilan komuta enjekte edilebiliyor.",
                            evidence=(
                                f"Payload: {payload!r} -> yanitta '{token}' marker'i TEK BASINA bulundu "
                                f"(gonderilen payload'in tamami yanitta yok, yani bu sadece yansitma degil -- "
                                f"echo komutu gercekten calistirilip ciktisi alinmis)."
                            ),
                            remediation="Kullanici girdisini shell'e asla dogrudan gecirmeyin; subprocess'i shell=False ve arguman listesiyle kullanin, girdiyi whitelist ile dogrulayin.",
                        )
                    )
                    break
    return findings
