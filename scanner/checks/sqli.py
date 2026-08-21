from core.crawler import Page
from core.http_client import HttpClient
from core.models import Category, Finding, Severity

DB_ERROR_SIGNATURES = (
    "sqlite3.operationalerror",
    "no such table",
    "no such column",
    "syntax error",
    "unrecognized token",
    "sql syntax",
    "sqlite3.",
)

# Bazi hedeflerde parametre tek bir sorgu icinde birden fazla kez kullanilabiliyor
# (bkz. vulnerable-app/VULNERABILITIES.md #1) -- basit tek-tirnak payload'lari boyle
# durumlarda quote sayisi kendini dengeleyip hata vermeyebiliyor. Bu yuzden hem klasik
# quote-tabanli hem de "-- " ile sorgunun geri kalanini kesen payload'lar birlikte denenir.
PAYLOADS = (
    "'",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "x' AND (SELECT 1 FROM pentestlab_nonexistent_table_xyz) -- ",
    "1' UNION SELECT NULL -- ",
    "') OR ('1'='1",
)


def _looks_like_db_error(text: str) -> bool:
    lowered = text.lower()
    return any(sig in lowered for sig in DB_ERROR_SIGNATURES)


def check_sqli(client: HttpClient, pages: list[Page]) -> list[Finding]:
    findings = []
    tested = set()

    for page in pages:
        for form in page.forms:
            input_names = tuple(i["name"] for i in form["inputs"])
            key = (form["action"], form["method"], input_names)
            if key in tested or not input_names:
                continue
            tested.add(key)

            for payload in PAYLOADS:
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

                if _looks_like_db_error(resp.text):
                    findings.append(
                        Finding(
                            title="SQL Injection",
                            severity=Severity.CRITICAL,
                            category=Category.WEB,
                            location=f"{form['method'].upper()} {form['action']}",
                            description=(
                                "Form alanina gonderilen payload veritabani hatasi tetikledi; "
                                "bu, SQL sorgusunun kullanici girdisiyle guvensiz sekilde "
                                "(string birlestirme ile) olusturuldugunu gosterir."
                            ),
                            evidence=f"Alan(lar): {list(data.keys())}, payload: {payload!r} -> yanitta DB hata imzasi bulundu.",
                            remediation="Parametreli sorgular (prepared statements) kullanin; kullanici girdisini asla SQL string'ine dogrudan gommeyin.",
                        )
                    )
                    break
    return findings
