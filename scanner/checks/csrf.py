from core.crawler import Page
from core.models import Category, Finding, Severity

TOKEN_NAME_HINTS = ("csrf", "token", "authenticity", "_token")
STATE_CHANGING_HINTS = ("update", "delete", "edit", "change", "remove", "admin", "settings", "password")


def check_csrf(pages: list[Page]) -> list[Finding]:
    findings = []
    seen = set()

    for page in pages:
        for form in page.forms:
            if form["method"] != "post":
                continue
            key = (form["action"], form["method"])
            if key in seen:
                continue
            seen.add(key)

            has_token = any(
                any(hint in inp["name"].lower() for hint in TOKEN_NAME_HINTS) for inp in form["inputs"]
            )
            if has_token:
                continue

            is_state_changing = any(hint in form["action"].lower() for hint in STATE_CHANGING_HINTS)
            severity = Severity.HIGH if is_state_changing else Severity.MEDIUM

            findings.append(
                Finding(
                    title="Eksik CSRF Koruması",
                    severity=severity,
                    category=Category.WEB,
                    location=f"POST {form['action']}",
                    description="Bu POST formunda anti-CSRF token bulunmuyor; oturum acmis bir kullanici, baska bir siteden bu istegi forge edilmis sekilde tetiklenebilir.",
                    evidence=f"Form input'lari: {[i['name'] for i in form['inputs']]} -- csrf/token adinda bir alan yok.",
                    remediation="Her state-changing form'a sunucu tarafinda dogrulanan, tahmin edilemez bir CSRF token ekleyin (ör. Flask-WTF CSRFProtect, Flask-SeaSurf).",
                )
            )
    return findings
